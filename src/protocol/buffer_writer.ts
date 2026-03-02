import { utf8Encode } from "../utils/encoding.ts";

export class SSHBufferWriter {
  #buffer: Uint8Array;
  #view: DataView;
  #offset = 0;

  constructor(initialCapacity = 256) {
    this.#buffer = new Uint8Array(initialCapacity);
    this.#view = new DataView(this.#buffer.buffer);
  }

  #ensure(bytes: number): void {
    const needed = this.#offset + bytes;
    if (needed <= this.#buffer.length) return;
    let newSize = this.#buffer.length * 2;
    while (newSize < needed) newSize *= 2;
    const newBuf = new Uint8Array(newSize);
    newBuf.set(this.#buffer);
    this.#buffer = newBuf;
    this.#view = new DataView(this.#buffer.buffer);
  }

  writeByte(v: number): this {
    this.#ensure(1);
    this.#buffer[this.#offset++] = v & 0xff;
    return this;
  }

  writeBoolean(v: boolean): this {
    return this.writeByte(v ? 1 : 0);
  }

  writeUint32(v: number): this {
    this.#ensure(4);
    this.#view.setUint32(this.#offset, v >>> 0);
    this.#offset += 4;
    return this;
  }

  writeUint64(v: bigint): this {
    this.#ensure(8);
    this.#view.setBigUint64(this.#offset, v);
    this.#offset += 8;
    return this;
  }

  writeString(data: Uint8Array): this {
    this.writeUint32(data.length);
    this.writeRawBytes(data);
    return this;
  }

  writeStringFromUTF8(s: string): this {
    return this.writeString(utf8Encode(s));
  }

  writeMpint(v: bigint): this {
    if (v === 0n) {
      return this.writeUint32(0);
    }

    const negative = v < 0n;
    let abs = negative ? -v : v;

    // Convert to bytes (big-endian)
    const bytes: number[] = [];
    while (abs > 0n) {
      bytes.unshift(Number(abs & 0xffn));
      abs >>= 8n;
    }

    if (negative) {
      // Two's complement: invert all bits and add 1
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = ~bytes[i] & 0xff;
      }
      // Add 1
      let carry = 1;
      for (let i = bytes.length - 1; i >= 0 && carry; i--) {
        const sum = bytes[i] + carry;
        bytes[i] = sum & 0xff;
        carry = sum >> 8;
      }
      // Ensure MSB has bit 7 set (negative)
      if ((bytes[0] & 0x80) === 0) {
        bytes.unshift(0xff);
      }
    } else {
      // Positive: ensure MSB doesn't have bit 7 set
      if ((bytes[0] & 0x80) !== 0) {
        bytes.unshift(0);
      }
    }

    this.writeUint32(bytes.length);
    this.#ensure(bytes.length);
    for (const b of bytes) {
      this.#buffer[this.#offset++] = b;
    }
    return this;
  }

  writeNameList(names: string[]): this {
    return this.writeStringFromUTF8(names.join(","));
  }

  writeRawBytes(data: Uint8Array): this {
    this.#ensure(data.length);
    this.#buffer.set(data, this.#offset);
    this.#offset += data.length;
    return this;
  }

  toBytes(): Uint8Array {
    return this.#buffer.slice(0, this.#offset);
  }

  get length(): number {
    return this.#offset;
  }
}
