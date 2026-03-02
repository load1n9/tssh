import * as C from "../protocol/constants.ts";
import {
  DEFAULT_MAX_PACKET_SIZE,
  DEFAULT_WINDOW_SIZE,
} from "../protocol/constants.ts";
import type { SSHMessage } from "../protocol/messages.ts";
import type { TransportHandler } from "../transport/transport_handler.ts";
import { SSHChannelError } from "../utils/errors.ts";
import { Channel, ChannelState } from "./channel.ts";
import { WindowManager } from "./window_manager.ts";

export class ChannelManager {
  #channels = new Map<number, Channel>();
  #nextLocalId = 0;
  #pendingOpens = new Map<
    number,
    {
      resolve: (channel: Channel) => void;
      reject: (error: Error) => void;
    }
  >();
  #incomingChannelHandler?: (channel: Channel) => void;

  constructor(private transport: TransportHandler) {
    transport.on("message", (msg: SSHMessage) => this.#handleMessage(msg));
  }

  onIncomingChannel(handler: (channel: Channel) => void): void {
    this.#incomingChannelHandler = handler;
  }

  async openChannel(
    channelType: string,
    extraData: Uint8Array = new Uint8Array(0),
  ): Promise<Channel> {
    const localId = this.#nextLocalId++;
    const localWindow = new WindowManager(
      DEFAULT_WINDOW_SIZE,
      DEFAULT_MAX_PACKET_SIZE,
    );
    const remoteWindow = new WindowManager(0, 0); // will be set on confirm

    const channel = new Channel(
      localId,
      0, // remote ID set on confirm
      channelType,
      localWindow,
      remoteWindow,
      this.transport,
    );

    this.#channels.set(localId, channel);

    await this.transport.sendMessage({
      type: C.SSH_MSG_CHANNEL_OPEN,
      channelType,
      senderChannel: localId,
      initialWindowSize: DEFAULT_WINDOW_SIZE,
      maximumPacketSize: DEFAULT_MAX_PACKET_SIZE,
      extraData,
    });

    return new Promise((resolve, reject) => {
      this.#pendingOpens.set(localId, { resolve, reject });

      setTimeout(() => {
        if (this.#pendingOpens.has(localId)) {
          this.#pendingOpens.delete(localId);
          this.#channels.delete(localId);
          reject(new SSHChannelError("Channel open timeout", localId));
        }
      }, 30000);
    });
  }

  #handleMessage(msg: SSHMessage): void {
    switch (msg.type) {
      case C.SSH_MSG_CHANNEL_OPEN:
        this.#handleChannelOpen(msg);
        break;
      case C.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
        this.#handleChannelOpenConfirm(msg);
        break;
      case C.SSH_MSG_CHANNEL_OPEN_FAILURE:
        this.#handleChannelOpenFailure(msg);
        break;
      case C.SSH_MSG_CHANNEL_WINDOW_ADJUST: {
        const ch = this.#channels.get(msg.recipientChannel);
        if (ch) ch.handleWindowAdjust(msg.bytesToAdd);
        break;
      }
      case C.SSH_MSG_CHANNEL_DATA: {
        const ch = this.#channels.get(msg.recipientChannel);
        if (ch) ch.handleData(msg.data);
        break;
      }
      case C.SSH_MSG_CHANNEL_EXTENDED_DATA: {
        const ch = this.#channels.get(msg.recipientChannel);
        if (ch) ch.handleExtendedData(msg.dataTypeCode, msg.data);
        break;
      }
      case C.SSH_MSG_CHANNEL_EOF: {
        const ch = this.#channels.get(msg.recipientChannel);
        if (ch) ch.handleEof();
        break;
      }
      case C.SSH_MSG_CHANNEL_CLOSE: {
        const ch = this.#channels.get(msg.recipientChannel);
        if (ch) {
          // Send close back if we haven't already
          if (ch.state !== ChannelState.Closed) {
            ch.close().catch(() => {});
          }
          ch.handleClose();
          this.#channels.delete(ch.localId);
        }
        break;
      }
      case C.SSH_MSG_CHANNEL_REQUEST: {
        const ch = this.#channels.get(msg.recipientChannel);
        if (ch) ch.handleRequest(msg);
        break;
      }
      case C.SSH_MSG_CHANNEL_SUCCESS: {
        const ch = this.#channels.get(msg.recipientChannel);
        if (ch) ch.handleRequestReply(true);
        break;
      }
      case C.SSH_MSG_CHANNEL_FAILURE: {
        const ch = this.#channels.get(msg.recipientChannel);
        if (ch) ch.handleRequestReply(false);
        break;
      }
    }
  }

  #handleChannelOpen(msg: {
    channelType: string;
    senderChannel: number;
    initialWindowSize: number;
    maximumPacketSize: number;
    extraData: Uint8Array;
  }): void {
    const localId = this.#nextLocalId++;
    const localWindow = new WindowManager(
      DEFAULT_WINDOW_SIZE,
      DEFAULT_MAX_PACKET_SIZE,
    );
    const remoteWindow = new WindowManager(
      msg.initialWindowSize,
      msg.maximumPacketSize,
    );

    const channel = new Channel(
      localId,
      msg.senderChannel,
      msg.channelType,
      localWindow,
      remoteWindow,
      this.transport,
    );
    channel.state = ChannelState.Open;
    channel.extraData = msg.extraData;

    this.#channels.set(localId, channel);

    // Send confirmation
    this.transport
      .sendMessage({
        type: C.SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
        recipientChannel: msg.senderChannel,
        senderChannel: localId,
        initialWindowSize: DEFAULT_WINDOW_SIZE,
        maximumPacketSize: DEFAULT_MAX_PACKET_SIZE,
        extraData: new Uint8Array(0),
      })
      .catch(() => {});

    if (this.#incomingChannelHandler) {
      this.#incomingChannelHandler(channel);
    }
  }

  #handleChannelOpenConfirm(msg: {
    recipientChannel: number;
    senderChannel: number;
    initialWindowSize: number;
    maximumPacketSize: number;
  }): void {
    const pending = this.#pendingOpens.get(msg.recipientChannel);
    const channel = this.#channels.get(msg.recipientChannel);

    if (pending && channel) {
      this.#pendingOpens.delete(msg.recipientChannel);
      channel.setOpen(
        msg.senderChannel,
        msg.initialWindowSize,
        msg.maximumPacketSize,
      );
      pending.resolve(channel);
    }
  }

  #handleChannelOpenFailure(msg: {
    recipientChannel: number;
    reasonCode: number;
    description: string;
  }): void {
    const pending = this.#pendingOpens.get(msg.recipientChannel);
    if (pending) {
      this.#pendingOpens.delete(msg.recipientChannel);
      this.#channels.delete(msg.recipientChannel);
      pending.reject(
        new SSHChannelError(
          `Channel open failed: ${msg.description} (code ${msg.reasonCode})`,
          msg.recipientChannel,
        ),
      );
    }
  }

  getChannel(localId: number): Channel | undefined {
    return this.#channels.get(localId);
  }

  async closeAll(): Promise<void> {
    for (const channel of this.#channels.values()) {
      try {
        await channel.close();
      } catch (_) {
        /* ignore */
      }
    }
    this.#channels.clear();
  }
}
