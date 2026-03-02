import type { Channel } from "../connection/channel.ts";
import type { ChannelManager } from "../connection/channel_manager.ts";
import {
  buildForwardedTcpipExtraData,
  parseDirectTcpipExtraData,
  pipeChannelToTcp,
} from "../connection/forwarding_channel.ts";
import type { GlobalRequestHandler } from "../connection/global_request.ts";
import { SSHBufferReader } from "../protocol/buffer_reader.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";

export class ServerForwardManager {
  #listeners = new Map<string, Deno.TcpListener>();
  #channelManager: ChannelManager;
  #globalRequests: GlobalRequestHandler;

  constructor(
    channelManager: ChannelManager,
    globalRequests: GlobalRequestHandler,
  ) {
    this.#channelManager = channelManager;
    this.#globalRequests = globalRequests;
    // Handle tcpip-forward and cancel-tcpip-forward global requests
    globalRequests.onRequest(async (name, _wantReply, data) => {
      const r = new SSHBufferReader(data);

      if (name === "tcpip-forward") {
        const address = r.readStringAsUTF8();
        const port = r.readUint32();
        const actualPort = await this.#startForward(address, port);
        if (actualPort !== null) {
          const w = new SSHBufferWriter(8);
          w.writeUint32(actualPort);
          return w.toBytes();
        }
        return false;
      }

      if (name === "cancel-tcpip-forward") {
        const address = r.readStringAsUTF8();
        const port = r.readUint32();
        this.cancelForward(address, port);
        return true;
      }

      return false;
    });
  }

  /** Handle incoming direct-tcpip channels */
  async handleDirectTcpip(
    channel: Channel,
    extraData: Uint8Array,
  ): Promise<void> {
    const { destHost, destPort } = parseDirectTcpipExtraData(extraData);

    try {
      const tcpConn = await Deno.connect({
        hostname: destHost,
        port: destPort,
        transport: "tcp",
      });
      await pipeChannelToTcp(channel, tcpConn);
    } catch (_) {
      await channel.close();
    }
  }

  // deno-lint-ignore require-await
  async #startForward(address: string, port: number): Promise<number | null> {
    try {
      const listener = Deno.listen({
        hostname: address,
        port,
        transport: "tcp",
      });

      const actualPort = (listener.addr as Deno.NetAddr).port;
      const key = `${address}:${actualPort}`;
      this.#listeners.set(key, listener);

      (async () => {
        try {
          for await (const conn of listener) {
            this.#handleForwardedConnection(conn, address, actualPort);
          }
        } catch (_) {
          // Listener closed
        }
      })();

      return actualPort;
    } catch (_) {
      return null;
    }
  }

  async #handleForwardedConnection(
    tcpConn: Deno.TcpConn,
    boundAddress: string,
    boundPort: number,
  ): Promise<void> {
    const remoteAddr = tcpConn.remoteAddr;
    const extraData = buildForwardedTcpipExtraData(
      boundAddress,
      boundPort,
      remoteAddr.hostname,
      remoteAddr.port,
    );

    try {
      const channel = await this.#channelManager.openChannel(
        "forwarded-tcpip",
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

  cancelForward(address: string, port: number): void {
    const key = `${address}:${port}`;
    const listener = this.#listeners.get(key);
    if (listener) {
      listener.close();
      this.#listeners.delete(key);
    }
  }

  closeAll(): void {
    for (const listener of this.#listeners.values()) {
      try {
        listener.close();
      } catch (_) {
        /* ignore */
      }
    }
    this.#listeners.clear();
  }
}
