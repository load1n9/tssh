import { randomBytes } from "../crypto/random.ts";
import { MAX_PACKET_SIZE, MIN_PADDING } from "../protocol/constants.ts";
import { concatBytes } from "../utils/encoding.ts";
import { SSHProtocolError } from "../utils/errors.ts";

/**
 * Raw binary packet framing for SSH.
 * Handles reading/writing the basic packet structure:
 *   uint32 packet_length | byte padding_length | payload | random_padding
 *
 * Does NOT handle encryption or MAC - that's PacketCodec's job.
 */
export class PacketIO {
  #readBuffer: Uint8Array = new Uint8Array(0);
  reader: ReadableStreamDefaultReader<Uint8Array>;
  writer: WritableStreamDefaultWriter<Uint8Array>;
  #closed = false;

  constructor(
    readable: ReadableStream<Uint8Array>,
    writable: WritableStream<Uint8Array>,
  ) {
    this.reader = readable.getReader();
    this.writer = writable.getWriter();
  }

  /** Read exactly `n` bytes from the stream, buffering as needed */
  async readExact(n: number): Promise<Uint8Array> {
    while (this.#readBuffer.length < n) {
      const { value, done } = await this.reader.read();
      if (done || !value) {
        throw new SSHProtocolError("Connection closed while reading packet");
      }
      this.#readBuffer = concatBytes(this.#readBuffer, value);
    }

    const result = this.#readBuffer.slice(0, n);
    this.#readBuffer = this.#readBuffer.slice(n);
    return result;
  }

  /** Prepend unconsumed bytes back into the read buffer */
  unread(data: Uint8Array): void {
    if (data.length > 0) {
      this.#readBuffer = concatBytes(data, this.#readBuffer);
    }
  }

  /** Read a plaintext (unencrypted) packet, returns the payload */
  async readPlaintextPacket(): Promise<Uint8Array> {
    // Read packet_length (4 bytes)
    const lenBuf = await this.readExact(4);
    const view = new DataView(lenBuf.buffer, lenBuf.byteOffset, 4);
    const packetLength = view.getUint32(0);

    if (packetLength > MAX_PACKET_SIZE || packetLength < 2) {
      throw new SSHProtocolError(`Invalid packet length: ${packetLength}`);
    }

    // Read the rest: padding_length + payload + padding
    const rest = await this.readExact(packetLength);
    const paddingLength = rest[0];
    const payloadLength = packetLength - paddingLength - 1;

    if (payloadLength < 0) {
      throw new SSHProtocolError("Invalid padding length");
    }

    return rest.slice(1, 1 + payloadLength);
  }

  /** Write a plaintext (unencrypted) packet */
  async writePlaintextPacket(payload: Uint8Array): Promise<void> {
    const blockSize = 8; // minimum for plaintext
    const paddingLength = computePaddingLength(payload.length, blockSize);
    const packetLength = 1 + payload.length + paddingLength;

    const packet = new Uint8Array(4 + packetLength);
    const view = new DataView(packet.buffer);
    view.setUint32(0, packetLength);
    packet[4] = paddingLength;
    packet.set(payload, 5);
    packet.set(randomBytes(paddingLength), 5 + payload.length);

    await this.writer.write(packet);
  }

  async writeRaw(data: Uint8Array): Promise<void> {
    await this.writer.write(data);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    try {
      this.reader.releaseLock();
    } catch (_) {
      /* ignore */
    }
    try {
      this.writer.releaseLock();
    } catch (_) {
      /* ignore */
    }
  }

  get closed(): boolean {
    return this.#closed;
  }
}

export function computePaddingLength(
  payloadLength: number,
  blockSize: number,
): number {
  const bs = Math.max(blockSize, 8);
  // total = 4(packet_length) + 1(padding_length) + payload + padding
  // must be multiple of blockSize
  const unpadded = 5 + payloadLength;
  let padding = bs - (unpadded % bs);
  if (padding < MIN_PADDING) padding += bs;
  return padding;
}

export function buildPacketBytes(
  payload: Uint8Array,
  blockSize: number,
): Uint8Array {
  const paddingLength = computePaddingLength(payload.length, blockSize);
  const packetLength = 1 + payload.length + paddingLength;

  const packet = new Uint8Array(4 + packetLength);
  const view = new DataView(packet.buffer);
  view.setUint32(0, packetLength);
  packet[4] = paddingLength;
  packet.set(payload, 5);
  packet.set(randomBytes(paddingLength), 5 + payload.length);

  return packet;
}
