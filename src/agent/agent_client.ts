import type { Channel } from "../connection/channel.ts";
import { concatBytes } from "../utils/encoding.ts";
import * as AC from "./agent_constants.ts";
import {
  type AgentIdentity,
  decodeIdentitiesAnswer,
  decodeSignResponse,
  encodeRequestIdentities,
  encodeSignRequest,
} from "./agent_protocol.ts";

/**
 * SSH Agent client that communicates over an auth-agent@openssh.com channel.
 */
export class AgentClient {
  #readBuffer: Uint8Array = new Uint8Array(0);
  #pendingReads: Array<{
    resolve: (data: Uint8Array) => void;
    reject: (err: Error) => void;
  }> = [];

  constructor(private channel: Channel) {
    this.#startReadLoop();
  }

  #startReadLoop(): void {
    (async () => {
      try {
        for await (const chunk of this.channel.readData()) {
          this.#readBuffer = concatBytes(this.#readBuffer, chunk);
          this.#processBuffer();
        }
      } catch (_) {
        // Channel closed
      }
      for (const pending of this.#pendingReads) {
        pending.reject(new Error("Agent channel closed"));
      }
      this.#pendingReads = [];
    })();
  }

  #processBuffer(): void {
    while (this.#readBuffer.length >= 4) {
      const view = new DataView(
        this.#readBuffer.buffer,
        this.#readBuffer.byteOffset,
        4,
      );
      const msgLen = view.getUint32(0);
      if (this.#readBuffer.length < 4 + msgLen) break;

      const fullMessage = this.#readBuffer.slice(0, 4 + msgLen);
      this.#readBuffer = this.#readBuffer.slice(4 + msgLen);

      if (this.#pendingReads.length > 0) {
        const pending = this.#pendingReads.shift()!;
        pending.resolve(fullMessage);
      }
    }
  }

  async #send(data: Uint8Array): Promise<void> {
    await this.channel.write(data);
  }

  #receive(): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      this.#pendingReads.push({ resolve, reject });
    });
  }

  async requestIdentities(): Promise<AgentIdentity[]> {
    await this.#send(encodeRequestIdentities());
    const response = await this.#receive();

    // Check for failure
    if (response[4] === AC.SSH_AGENT_FAILURE) {
      throw new Error("Agent refused to list identities");
    }

    return decodeIdentitiesAnswer(response);
  }

  async sign(
    publicKey: Uint8Array,
    data: Uint8Array,
    flags?: number,
  ): Promise<Uint8Array> {
    await this.#send(encodeSignRequest(publicKey, data, flags ?? 0));
    const response = await this.#receive();

    if (response[4] === AC.SSH_AGENT_FAILURE) {
      throw new Error("Agent refused to sign");
    }

    return decodeSignResponse(response);
  }
}
