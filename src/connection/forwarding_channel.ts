import { SSHBufferReader } from "../protocol/buffer_reader.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";
import type { Channel } from "./channel.ts";
import type { ChannelManager } from "./channel_manager.ts";

export interface LocalForwardConfig {
  bindAddress: string;
  bindPort: number;
  destHost: string;
  destPort: number;
}

export interface RemoteForwardConfig {
  bindAddress: string;
  bindPort: number;
  destHost: string;
  destPort: number;
}

/**
 * Opens a direct-tcpip channel for local port forwarding.
 * Extra data format:
 *   string host_to_connect | uint32 port_to_connect |
 *   string originator_address | uint32 originator_port
 */
export function buildDirectTcpipExtraData(
  destHost: string,
  destPort: number,
  originAddr: string,
  originPort: number,
): Uint8Array {
  const w = new SSHBufferWriter(128);
  w.writeStringFromUTF8(destHost);
  w.writeUint32(destPort);
  w.writeStringFromUTF8(originAddr);
  w.writeUint32(originPort);
  return w.toBytes();
}

/**
 * Parse extra data from a direct-tcpip channel open
 */
export function parseDirectTcpipExtraData(data: Uint8Array): {
  destHost: string;
  destPort: number;
  originAddr: string;
  originPort: number;
} {
  const r = new SSHBufferReader(data);
  return {
    destHost: r.readStringAsUTF8(),
    destPort: r.readUint32(),
    originAddr: r.readStringAsUTF8(),
    originPort: r.readUint32(),
  };
}

/**
 * Build extra data for a forwarded-tcpip channel open.
 *   string connected_address | uint32 connected_port |
 *   string originator_address | uint32 originator_port
 */
export function buildForwardedTcpipExtraData(
  connectedAddress: string,
  connectedPort: number,
  originAddr: string,
  originPort: number,
): Uint8Array {
  const w = new SSHBufferWriter(128);
  w.writeStringFromUTF8(connectedAddress);
  w.writeUint32(connectedPort);
  w.writeStringFromUTF8(originAddr);
  w.writeUint32(originPort);
  return w.toBytes();
}

export function parseForwardedTcpipExtraData(data: Uint8Array): {
  connectedAddress: string;
  connectedPort: number;
  originAddr: string;
  originPort: number;
} {
  const r = new SSHBufferReader(data);
  return {
    connectedAddress: r.readStringAsUTF8(),
    connectedPort: r.readUint32(),
    originAddr: r.readStringAsUTF8(),
    originPort: r.readUint32(),
  };
}

/**
 * Bidirectional pipe between a Channel and a TCP connection.
 * Returns when either side closes.
 */
export async function pipeChannelToTcp(
  channel: Channel,
  tcpConn: Deno.Conn,
): Promise<void> {
  const tcpReadable = tcpConn.readable;
  const tcpWritable = tcpConn.writable;

  // TCP -> Channel
  const tcpToChannel = (async () => {
    try {
      const reader = tcpReadable.getReader();
      while (true) {
        const { value, done } = await reader.read();
        if (done || !value) break;
        await channel.write(value);
      }
      await channel.sendEof();
    } catch (_) {
      // Connection may close abruptly
    }
  })();

  // Channel -> TCP
  const channelToTcp = (async () => {
    try {
      const writer = tcpWritable.getWriter();
      for await (const data of channel.readData()) {
        await writer.write(data);
      }
      await writer.close();
    } catch (_) {
      // Connection may close abruptly
    }
  })();

  await Promise.allSettled([tcpToChannel, channelToTcp]);
}

/**
 * Manages local port forwarding.
 * Listens on a local port and forwards connections through SSH direct-tcpip channels.
 */
export class LocalForwardManager {
  #listeners = new Map<string, Deno.Listener>();
  #abortControllers = new Map<string, AbortController>();

  constructor(private channelManager: ChannelManager) {}

  // deno-lint-ignore require-await
  async addForward(config: LocalForwardConfig): Promise<void> {
    const key = `${config.bindAddress}:${config.bindPort}`;
    const listener = Deno.listen({
      hostname: config.bindAddress,
      port: config.bindPort,
      transport: "tcp",
    });
    this.#listeners.set(key, listener);
    const ac = new AbortController();
    this.#abortControllers.set(key, ac);

    (async () => {
      try {
        for await (const conn of listener) {
          if (ac.signal.aborted) break;
          this.handleLocalConnection(conn, config).catch(() => {});
        }
      } catch (_) {
        // Listener closed
      }
    })();
  }

  private async handleLocalConnection(
    tcpConn: Deno.Conn,
    config: LocalForwardConfig,
  ): Promise<void> {
    const remoteAddr = (tcpConn as Deno.TcpConn).remoteAddr;
    const extraData = buildDirectTcpipExtraData(
      config.destHost,
      config.destPort,
      remoteAddr.hostname,
      remoteAddr.port,
    );

    try {
      const channel = await this.channelManager.openChannel(
        "direct-tcpip",
        extraData,
      );
      await pipeChannelToTcp(channel, tcpConn);
    } catch (_) {
      try {
        tcpConn.close();
      } catch (_) {
        /* ignore */
      }
    }
  }

  removeForward(bindAddress: string, bindPort: number): void {
    const key = `${bindAddress}:${bindPort}`;
    const ac = this.#abortControllers.get(key);
    if (ac) ac.abort();
    const listener = this.#listeners.get(key);
    if (listener) listener.close();
    this.#listeners.delete(key);
    this.#abortControllers.delete(key);
  }

  closeAll(): void {
    for (const ac of this.#abortControllers.values()) ac.abort();
    for (const listener of this.#listeners.values()) {
      try {
        listener.close();
      } catch (_) {
        /* ignore */
      }
    }
    this.#listeners.clear();
    this.#abortControllers.clear();
  }
}
