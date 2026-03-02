import * as C from "../protocol/constants.ts";
import type { ChannelRequestMessage } from "../protocol/messages.ts";
import type { TransportHandler } from "../transport/transport_handler.ts";
import { AsyncQueue } from "../utils/async_queue.ts";
import { SSHChannelError } from "../utils/errors.ts";
import { TypedEventEmitter } from "../utils/event_emitter.ts";
import { WindowManager } from "./window_manager.ts";

export enum ChannelState {
  Opening = "opening",
  Open = "open",
  EofSent = "eof_sent",
  EofReceived = "eof_received",
  Closing = "closing",
  Closed = "closed",
}

export interface ChannelEvents {
  data: Uint8Array;
  extendedData: { dataType: number; data: Uint8Array };
  eof: void;
  close: void;
  request: ChannelRequestMessage;
  windowAdjust: number;
}

export class Channel extends TypedEventEmitter<ChannelEvents> {
  state: ChannelState = ChannelState.Opening;
  extraData: Uint8Array = new Uint8Array(0);
  #dataQueue = new AsyncQueue<Uint8Array>();
  #stderrQueue = new AsyncQueue<Uint8Array>();
  #requestReplyQueue = new AsyncQueue<boolean>();
  #transport: TransportHandler;
  constructor(
    public readonly localId: number,
    public remoteId: number,
    public readonly channelType: string,
    public readonly localWindow: WindowManager,
    public remoteWindow: WindowManager,
    transport: TransportHandler,
  ) {
    super();
    this.#transport = transport;
  }

  setOpen(
    remoteId: number,
    remoteWindowSize: number,
    remoteMaxPacket: number,
  ): void {
    this.remoteId = remoteId;
    this.remoteWindow = new WindowManager(remoteWindowSize, remoteMaxPacket);
    this.state = ChannelState.Open;
  }

  async write(data: Uint8Array): Promise<void> {
    if (
      this.state !== ChannelState.Open &&
      this.state !== ChannelState.EofReceived
    ) {
      throw new SSHChannelError(
        "Cannot write to channel in state: " + this.state,
        this.localId,
      );
    }

    let offset = 0;
    while (offset < data.length) {
      const maxChunk = Math.min(
        this.remoteWindow.maxPacketSize,
        this.remoteWindow.available,
        data.length - offset,
      );

      if (maxChunk <= 0) {
        await this.remoteWindow.waitForWindow(1);
        continue;
      }

      const chunk = data.subarray(offset, offset + maxChunk);
      await this.#transport.sendMessage({
        type: C.SSH_MSG_CHANNEL_DATA,
        recipientChannel: this.remoteId,
        data: chunk,
      });
      this.remoteWindow.consume(maxChunk);
      offset += maxChunk;
    }
  }

  async writeExtended(dataType: number, data: Uint8Array): Promise<void> {
    if (
      this.state !== ChannelState.Open &&
      this.state !== ChannelState.EofReceived
    ) {
      throw new SSHChannelError(
        "Cannot write to channel in state: " + this.state,
        this.localId,
      );
    }

    let offset = 0;
    while (offset < data.length) {
      const maxChunk = Math.min(
        this.remoteWindow.maxPacketSize,
        this.remoteWindow.available,
        data.length - offset,
      );

      if (maxChunk <= 0) {
        await this.remoteWindow.waitForWindow(1);
        continue;
      }

      const chunk = data.subarray(offset, offset + maxChunk);
      await this.#transport.sendMessage({
        type: C.SSH_MSG_CHANNEL_EXTENDED_DATA,
        recipientChannel: this.remoteId,
        dataTypeCode: dataType,
        data: chunk,
      });
      this.remoteWindow.consume(maxChunk);
      offset += maxChunk;
    }
  }

  /** Handle incoming data */
  handleData(data: Uint8Array): void {
    this.localWindow.consume(data.length);
    this.#dataQueue.push(data);
    this.emit("data", data);
    this.#maybeAdjustWindow();
  }

  /** Handle incoming extended data */
  handleExtendedData(dataType: number, data: Uint8Array): void {
    this.localWindow.consume(data.length);
    if (dataType === C.SSH_EXTENDED_DATA_STDERR) {
      this.#stderrQueue.push(data);
    }
    this.emit("extendedData", { dataType, data });
    this.#maybeAdjustWindow();
  }

  /** Handle incoming window adjust */
  handleWindowAdjust(bytesToAdd: number): void {
    this.remoteWindow.adjust(bytesToAdd);
    this.emit("windowAdjust", bytesToAdd);
  }

  /** Handle incoming EOF */
  handleEof(): void {
    if (this.state === ChannelState.EofSent) {
      this.state = ChannelState.Closing;
    } else {
      this.state = ChannelState.EofReceived;
    }
    this.#dataQueue.close();
    this.#stderrQueue.close();
    this.emit("eof", undefined as unknown as void);
  }

  /** Handle incoming close */
  handleClose(): void {
    this.state = ChannelState.Closed;
    this.#dataQueue.close();
    this.#stderrQueue.close();
    this.#requestReplyQueue.close();
    this.emit("close", undefined as unknown as void);
  }

  /** Handle incoming channel request */
  handleRequest(msg: ChannelRequestMessage): void {
    this.emit("request", msg);
  }

  /** Handle channel success/failure (reply to our requests) */
  handleRequestReply(success: boolean): void {
    this.#requestReplyQueue.push(success);
  }

  async sendEof(): Promise<void> {
    if (
      this.state === ChannelState.EofSent ||
      this.state === ChannelState.Closing ||
      this.state === ChannelState.Closed
    ) {
      return;
    }
    await this.#transport.sendMessage({
      type: C.SSH_MSG_CHANNEL_EOF,
      recipientChannel: this.remoteId,
    });
    if (this.state === ChannelState.EofReceived) {
      this.state = ChannelState.Closing;
    } else {
      this.state = ChannelState.EofSent;
    }
  }

  async close(): Promise<void> {
    if (this.state === ChannelState.Closed) return;
    await this.#transport.sendMessage({
      type: C.SSH_MSG_CHANNEL_CLOSE,
      recipientChannel: this.remoteId,
    });
    this.state = ChannelState.Closed;
    this.#dataQueue.close();
    this.#stderrQueue.close();
    this.#requestReplyQueue.close();
  }

  async sendRequest(
    requestType: string,
    wantReply: boolean,
    data: Uint8Array = new Uint8Array(0),
  ): Promise<boolean> {
    await this.#transport.sendMessage({
      type: C.SSH_MSG_CHANNEL_REQUEST,
      recipientChannel: this.remoteId,
      requestType,
      wantReply,
      requestData: data,
    });
    if (!wantReply) return true;
    const reply = await this.#requestReplyQueue.pop();
    return reply ?? false;
  }

  async sendSuccess(): Promise<void> {
    await this.#transport.sendMessage({
      type: C.SSH_MSG_CHANNEL_SUCCESS,
      recipientChannel: this.remoteId,
    });
  }

  async sendFailure(): Promise<void> {
    await this.#transport.sendMessage({
      type: C.SSH_MSG_CHANNEL_FAILURE,
      recipientChannel: this.remoteId,
    });
  }

  /** Read data as an async iterator */
  async *readData(): AsyncIterableIterator<Uint8Array> {
    for await (const chunk of this.#dataQueue) {
      yield chunk;
    }
  }

  /** Read stderr data as an async iterator */
  async *readStderr(): AsyncIterableIterator<Uint8Array> {
    for await (const chunk of this.#stderrQueue) {
      yield chunk;
    }
  }

  #maybeAdjustWindow(): void {
    if (this.localWindow.shouldAdjust()) {
      const amount = this.localWindow.getConsumedAndReset();
      this.localWindow.adjust(amount);
      this.#transport
        .sendMessage({
          type: C.SSH_MSG_CHANNEL_WINDOW_ADJUST,
          recipientChannel: this.remoteId,
          bytesToAdd: amount,
        })
        .catch(() => {});
    }
  }
}
