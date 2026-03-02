// deno-lint-ignore-file require-await
import { SSHBufferReader } from "../protocol/buffer_reader.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";
import { concatBytes } from "../utils/encoding.ts";
import type { Channel } from "./channel.ts";

export interface PtyOptions {
  term: string;
  cols: number;
  rows: number;
  widthPx: number;
  heightPx: number;
  modes?: Uint8Array;
}

export class SessionChannel {
  #exitCode: number | null = null;
  #exitSignal: string | null = null;
  #exitResolve?: (value: number) => void;
  #exitSignalResolve?: (value: string) => void;

  readonly exitStatus: Promise<number>;
  readonly exitSignalPromise: Promise<string>;

  constructor(public readonly channel: Channel) {
    this.exitStatus = new Promise((resolve) => {
      this.#exitResolve = resolve;
    });
    this.exitSignalPromise = new Promise((resolve) => {
      this.#exitSignalResolve = resolve;
    });

    // Listen for exit-status and exit-signal requests
    channel.on("request", (msg) => {
      const r = new SSHBufferReader(msg.requestData);
      switch (msg.requestType) {
        case "exit-status": {
          this.#exitCode = r.readUint32();
          if (this.#exitResolve) this.#exitResolve(this.#exitCode);
          break;
        }
        case "exit-signal": {
          this.#exitSignal = r.readStringAsUTF8();
          if (this.#exitSignalResolve) {
            this.#exitSignalResolve(this.#exitSignal);
          }
          break;
        }
      }
    });
  }

  async requestPty(opts: PtyOptions): Promise<boolean> {
    const w = new SSHBufferWriter(128);
    w.writeStringFromUTF8(opts.term);
    w.writeUint32(opts.cols);
    w.writeUint32(opts.rows);
    w.writeUint32(opts.widthPx);
    w.writeUint32(opts.heightPx);
    w.writeString(opts.modes ?? new Uint8Array([0])); // TTY_OP_END
    return this.channel.sendRequest("pty-req", true, w.toBytes());
  }

  async requestShell(): Promise<boolean> {
    return this.channel.sendRequest("shell", true);
  }

  async requestExec(command: string): Promise<boolean> {
    const w = new SSHBufferWriter(256);
    w.writeStringFromUTF8(command);
    return this.channel.sendRequest("exec", true, w.toBytes());
  }

  async requestSubsystem(name: string): Promise<boolean> {
    const w = new SSHBufferWriter(64);
    w.writeStringFromUTF8(name);
    return this.channel.sendRequest("subsystem", true, w.toBytes());
  }

  async setEnv(name: string, value: string): Promise<boolean> {
    const w = new SSHBufferWriter(128);
    w.writeStringFromUTF8(name);
    w.writeStringFromUTF8(value);
    return this.channel.sendRequest("env", true, w.toBytes());
  }

  async sendWindowChange(
    cols: number,
    rows: number,
    widthPx: number,
    heightPx: number,
  ): Promise<void> {
    const w = new SSHBufferWriter(32);
    w.writeUint32(cols);
    w.writeUint32(rows);
    w.writeUint32(widthPx);
    w.writeUint32(heightPx);
    await this.channel.sendRequest("window-change", false, w.toBytes());
  }

  async sendSignal(signal: string): Promise<void> {
    const w = new SSHBufferWriter(32);
    w.writeStringFromUTF8(signal);
    await this.channel.sendRequest("signal", false, w.toBytes());
  }

  async sendExitStatus(code: number): Promise<void> {
    const w = new SSHBufferWriter(8);
    w.writeUint32(code);
    await this.channel.sendRequest("exit-status", false, w.toBytes());
  }

  /** Write to stdin of the remote process */
  async write(data: Uint8Array): Promise<void> {
    await this.channel.write(data);
  }

  /** Read stdout from the remote process */
  async *readStdout(): AsyncIterableIterator<Uint8Array> {
    yield* this.channel.readData();
  }

  /** Read stderr from the remote process */
  async *readStderr(): AsyncIterableIterator<Uint8Array> {
    yield* this.channel.readStderr();
  }

  /** Collect all stdout into a single buffer */
  async collectStdout(): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of this.readStdout()) {
      chunks.push(chunk);
    }
    return concatBytes(...chunks);
  }

  /** Collect all stderr into a single buffer */
  async collectStderr(): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of this.readStderr()) {
      chunks.push(chunk);
    }
    return concatBytes(...chunks);
  }

  async close(): Promise<void> {
    await this.channel.sendEof();
    await this.channel.close();
  }

  get exitCode(): number | null {
    return this.#exitCode;
  }
  get exitSignalName(): string | null {
    return this.#exitSignal;
  }
}
