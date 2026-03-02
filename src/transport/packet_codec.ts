import type { AESCTRCipher } from "../crypto/aes_ctr.ts";
import type { HMACComputer } from "../crypto/hmac.ts";
import { randomBytes } from "../crypto/random.ts";
import { parseMessage } from "../protocol/message_parser.ts";
import { serializeMessage } from "../protocol/message_serializer.ts";
import type { SSHMessage } from "../protocol/messages.ts";
import { concatBytes } from "../utils/encoding.ts";
import { SSHCryptoError, SSHProtocolError } from "../utils/errors.ts";
import { computePaddingLength, type PacketIO } from "./packet_io.ts";
import { SequenceCounter } from "./sequence_counter.ts";

interface CryptoState {
  cipher: AESCTRCipher;
  hmac: HMACComputer;
  blockSize: number;
}

/**
 * Adds encryption and MAC on top of PacketIO.
 * Before keys are set, operates in plaintext mode.
 * After setEncryptionKeys/setDecryptionKeys, encrypts/decrypts packets.
 */
export class PacketCodec {
  #encryptState: CryptoState | null = null;
  #decryptState: CryptoState | null = null;
  #sendSeq = new SequenceCounter();
  #recvSeq = new SequenceCounter();
  #writeLock: Promise<void> = Promise.resolve();

  constructor(private io: PacketIO) {}

  setEncryptionKeys(
    cipher: AESCTRCipher,
    hmac: HMACComputer,
    blockSize: number,
  ): void {
    this.#encryptState = { cipher, hmac, blockSize };
  }

  setDecryptionKeys(
    cipher: AESCTRCipher,
    hmac: HMACComputer,
    blockSize: number,
  ): void {
    this.#decryptState = { cipher, hmac, blockSize };
  }

  get sendSequence(): SequenceCounter {
    return this.#sendSeq;
  }
  get recvSequence(): SequenceCounter {
    return this.#recvSeq;
  }

  async readMessage(): Promise<SSHMessage> {
    const payload = this.#decryptState
      ? await this.#readEncryptedPacket()
      : await this.#readPlaintextPacket();
    return parseMessage(payload);
  }

  async writeMessage(msg: SSHMessage): Promise<void> {
    const payload = serializeMessage(msg);
    await this.#serializedWrite(() =>
      this.#encryptState
        ? this.#writeEncryptedPacket(payload)
        : this.#writePlaintextPacket(payload)
    );
  }

  /** Write raw payload as a packet (used during kex before message types are finalized) */
  async writePayload(payload: Uint8Array): Promise<void> {
    await this.#serializedWrite(() =>
      this.#encryptState
        ? this.#writeEncryptedPacket(payload)
        : this.#writePlaintextPacket(payload)
    );
  }

  /** Serialize writes to prevent concurrent cipher/sequence corruption */
  #serializedWrite(fn: () => Promise<void>): Promise<void> {
    const prev = this.#writeLock;
    const next = prev.then(fn, fn);
    this.#writeLock = next.then(() => {}, () => {});
    return next;
  }

  /** Read raw payload from a packet */
  async readPayload(): Promise<Uint8Array> {
    if (this.#decryptState) {
      return await this.#readEncryptedPacket();
    } else {
      return await this.#readPlaintextPacket();
    }
  }

  // deno-lint-ignore require-await
  async #readPlaintextPacket(): Promise<Uint8Array> {
    const seq = this.#recvSeq.next();
    void seq; // sequence tracked but not used for plaintext
    return this.io.readPlaintextPacket();
  }

  async #writePlaintextPacket(payload: Uint8Array): Promise<void> {
    const seq = this.#sendSeq.next();
    void seq;
    await this.io.writePlaintextPacket(payload);
  }

  async #readEncryptedPacket(): Promise<Uint8Array> {
    const state = this.#decryptState!;
    const seqNum = this.#recvSeq.next();
    const blockSize = state.blockSize;

    // Phase 1: Read and decrypt first block to get packet_length
    const firstBlock = await this.io.readExact(blockSize);
    const decryptedFirst = await state.cipher.decrypt(firstBlock);

    const view = new DataView(
      decryptedFirst.buffer,
      decryptedFirst.byteOffset,
      4,
    );
    const packetLength = view.getUint32(0);

    if (packetLength > 35000 || packetLength < 2) {
      throw new SSHProtocolError(
        `Invalid encrypted packet length: ${packetLength}`,
      );
    }

    // Phase 2: Read remaining encrypted bytes
    const remaining = 4 + packetLength - blockSize;
    let decryptedRest: Uint8Array = new Uint8Array(0);
    if (remaining > 0) {
      const encryptedRest = await this.io.readExact(remaining);
      decryptedRest = await state.cipher.decrypt(encryptedRest);
    }

    // Phase 3: Read MAC
    const mac = await this.io.readExact(state.hmac.macLength);

    // Reassemble full decrypted packet (for MAC verification)
    const fullDecrypted = concatBytes(decryptedFirst, decryptedRest);

    // Phase 4: Verify MAC over sequence_number(4 BE) || unencrypted_packet
    const seqBuf = new Uint8Array(4);
    new DataView(seqBuf.buffer).setUint32(0, seqNum);
    const macInput = concatBytes(seqBuf, fullDecrypted);
    const valid = await state.hmac.verify(macInput, mac);
    if (!valid) {
      throw new SSHCryptoError("MAC verification failed");
    }

    // Extract payload (skip packet_length[4] + padding_length[1], strip padding)
    const paddingLength = fullDecrypted[4];
    const payloadLength = packetLength - paddingLength - 1;
    return fullDecrypted.slice(5, 5 + payloadLength);
  }

  async #writeEncryptedPacket(payload: Uint8Array): Promise<void> {
    const state = this.#encryptState!;
    const seqNum = this.#sendSeq.next();
    const blockSize = state.blockSize;

    // Build the unencrypted packet
    const paddingLength = computePaddingLength(payload.length, blockSize);
    const packetLength = 1 + payload.length + paddingLength;

    const packet = new Uint8Array(4 + packetLength);
    const view = new DataView(packet.buffer);
    view.setUint32(0, packetLength);
    packet[4] = paddingLength;
    packet.set(payload, 5);
    packet.set(randomBytes(paddingLength), 5 + payload.length);

    // Compute MAC over sequence_number(4 BE) || unencrypted_packet
    const seqBuf = new Uint8Array(4);
    new DataView(seqBuf.buffer).setUint32(0, seqNum);
    const macInput = concatBytes(seqBuf, packet);
    const mac = await state.hmac.compute(macInput);

    // Encrypt the packet (not the MAC)
    const encrypted = await state.cipher.encrypt(packet);

    // Write encrypted packet + MAC
    await this.io.writeRaw(concatBytes(encrypted, mac));
  }

  close(): void {
    this.io.close();
  }
}
