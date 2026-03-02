import type { Channel } from "../connection/channel.ts";
import type { PtyOptions } from "../connection/session_channel.ts";
import { SSHBufferReader } from "../protocol/buffer_reader.ts";
import type { ChannelRequestMessage } from "../protocol/messages.ts";
import { SftpServer } from "../sftp/sftp_server.ts";
import { TypedEventEmitter } from "../utils/event_emitter.ts";

export interface SessionEvents {
  pty: PtyOptions;
  shell: void;
  exec: { command: string };
  subsystem: { name: string };
  env: { name: string; value: string };
  windowChange: {
    cols: number;
    rows: number;
    widthPx: number;
    heightPx: number;
  };
  signal: { signal: string };
  eof: void;
  close: void;
}

export class ServerSession extends TypedEventEmitter<SessionEvents> {
  constructor(public readonly channel: Channel) {
    super();
    channel.on("request", (msg) => this.#handleRequest(msg));
    channel.on("eof", () => this.emit("eof", undefined as unknown as void));
    channel.on("close", () => this.emit("close", undefined as unknown as void));
  }

  async #handleRequest(msg: ChannelRequestMessage): Promise<void> {
    const r = new SSHBufferReader(msg.requestData);

    switch (msg.requestType) {
      case "pty-req": {
        const term = r.readStringAsUTF8();
        const cols = r.readUint32();
        const rows = r.readUint32();
        const widthPx = r.readUint32();
        const heightPx = r.readUint32();
        const modes = r.readString();
        if (msg.wantReply) await this.channel.sendSuccess();
        this.emit("pty", { term, cols, rows, widthPx, heightPx, modes });
        break;
      }

      case "shell": {
        if (msg.wantReply) await this.channel.sendSuccess();
        this.emit("shell", undefined as unknown as void);
        break;
      }

      case "exec": {
        const command = r.readStringAsUTF8();
        if (msg.wantReply) await this.channel.sendSuccess();
        this.emit("exec", { command });
        break;
      }

      case "subsystem": {
        const name = r.readStringAsUTF8();
        if (msg.wantReply) await this.channel.sendSuccess();
        if (name === "sftp") {
          // Auto-start SFTP server
          const sftp = new SftpServer(this.channel);
          sftp.serve().catch(() => {});
        }
        this.emit("subsystem", { name });
        break;
      }

      case "env": {
        const name = r.readStringAsUTF8();
        const value = r.readStringAsUTF8();
        if (msg.wantReply) await this.channel.sendSuccess();
        this.emit("env", { name, value });
        break;
      }

      case "window-change": {
        const cols = r.readUint32();
        const rows = r.readUint32();
        const widthPx = r.readUint32();
        const heightPx = r.readUint32();
        this.emit("windowChange", { cols, rows, widthPx, heightPx });
        break;
      }

      case "signal": {
        const signal = r.readStringAsUTF8();
        this.emit("signal", { signal });
        break;
      }

      default: {
        if (msg.wantReply) await this.channel.sendFailure();
        break;
      }
    }
  }

  /** Write data to the channel (send to client stdout) */
  async write(data: Uint8Array): Promise<void> {
    await this.channel.write(data);
  }

  /** Write to stderr */
  async writeStderr(data: Uint8Array): Promise<void> {
    await this.channel.writeExtended(1, data);
  }

  /** Send exit status and close */
  async exit(code: number): Promise<void> {
    const { SSHBufferWriter } = await import("../protocol/buffer_writer.ts");
    const w = new SSHBufferWriter(8);
    w.writeUint32(code);
    await this.channel.sendRequest("exit-status", false, w.toBytes());
    await this.channel.sendEof();
    await this.channel.close();
  }
}
