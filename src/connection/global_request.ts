import { SSHBufferReader } from "../protocol/buffer_reader.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";
import * as C from "../protocol/constants.ts";
import type { SSHMessage } from "../protocol/messages.ts";
import type { TransportHandler } from "../transport/transport_handler.ts";
import { AsyncQueue } from "../utils/async_queue.ts";

export class GlobalRequestHandler {
  #replyQueue = new AsyncQueue<{ success: boolean; data: Uint8Array }>();
  #requestHandler?: (
    requestName: string,
    wantReply: boolean,
    data: Uint8Array,
  ) => Promise<Uint8Array | boolean>;
  #transport: TransportHandler;
  constructor(transport: TransportHandler) {
    this.#transport = transport;
    transport.on("message", (msg: SSHMessage) => {
      switch (msg.type) {
        case C.SSH_MSG_REQUEST_SUCCESS:
          this.#replyQueue.push({ success: true, data: msg.data });
          break;
        case C.SSH_MSG_REQUEST_FAILURE:
          this.#replyQueue.push({ success: false, data: new Uint8Array(0) });
          break;
        case C.SSH_MSG_GLOBAL_REQUEST:
          this.#handleIncomingRequest(msg.requestName, msg.wantReply, msg.data);
          break;
      }
    });
  }

  onRequest(
    handler: (
      requestName: string,
      wantReply: boolean,
      data: Uint8Array,
    ) => Promise<Uint8Array | boolean>,
  ): void {
    this.#requestHandler = handler;
  }

  async sendRequest(
    requestName: string,
    wantReply: boolean,
    data: Uint8Array = new Uint8Array(0),
  ): Promise<Uint8Array | null> {
    await this.#transport.sendMessage({
      type: C.SSH_MSG_GLOBAL_REQUEST,
      requestName,
      wantReply,
      data,
    });

    if (!wantReply) return null;

    const reply = await this.#replyQueue.pop();
    if (!reply || !reply.success) return null;
    return reply.data;
  }

  /** Send a tcpip-forward request */
  async requestTcpipForward(
    bindAddress: string,
    bindPort: number,
  ): Promise<number | null> {
    const w = new SSHBufferWriter(64);
    w.writeStringFromUTF8(bindAddress);
    w.writeUint32(bindPort);

    const reply = await this.sendRequest("tcpip-forward", true, w.toBytes());
    if (!reply) return null;

    if (bindPort === 0 && reply.length >= 4) {
      const r = new SSHBufferReader(reply);
      return r.readUint32();
    }
    return bindPort;
  }

  /** Send a cancel-tcpip-forward request */
  async cancelTcpipForward(
    bindAddress: string,
    bindPort: number,
  ): Promise<boolean> {
    const w = new SSHBufferWriter(64);
    w.writeStringFromUTF8(bindAddress);
    w.writeUint32(bindPort);

    const reply = await this.sendRequest(
      "cancel-tcpip-forward",
      true,
      w.toBytes(),
    );
    return reply !== null;
  }

  async #handleIncomingRequest(
    requestName: string,
    wantReply: boolean,
    data: Uint8Array,
  ): Promise<void> {
    if (this.#requestHandler) {
      try {
        const result = await this.#requestHandler(requestName, wantReply, data);
        if (wantReply) {
          if (result === false) {
            await this.#transport.sendMessage({
              type: C.SSH_MSG_REQUEST_FAILURE,
            });
          } else {
            const responseData = result === true ? new Uint8Array(0) : result;
            await this.#transport.sendMessage({
              type: C.SSH_MSG_REQUEST_SUCCESS,
              data: responseData,
            });
          }
        }
      } catch (_) {
        if (wantReply) {
          await this.#transport.sendMessage({
            type: C.SSH_MSG_REQUEST_FAILURE,
          });
        }
      }
    } else if (wantReply) {
      await this.#transport.sendMessage({ type: C.SSH_MSG_REQUEST_FAILURE });
    }
  }
}
