import { utf8Decode } from "../utils/encoding.ts";
import { SSHProtocolError } from "../utils/errors.ts";

export class SSHBufferReader {
  #view: DataView;
  #offset = 0;
  #data: Uint8Array;

  constructor(data: Uint8Array) {
    this.#data = data;
    this.#view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  #check(n: number): void {
    if (this.#offset + n > this.#data.length) {
      throw new SSHProtocolError(
        `Buffer underflow: need ${n} bytes at offset ${this.#offset}, have ${
          this.#data.length - this.#offset
        }`,
      );
    }
  }

  readByte(): number {
    this.#check(1);
    return this.#data[this.#offset++];
  }

  readBoolean(): boolean {
    return this.readByte() !== 0;
  }

  readUint32(): number {
    this.#check(4);
    const v = this.#view.getUint32(this.#offset);
    this.#offset += 4;
    return v;
  }

  readUint64(): bigint {
    this.#check(8);
    const v = this.#view.getBigUint64(this.#offset);
    this.#offset += 8;
    return v;
  }

  readString(): Uint8Array {
    const len = this.readUint32();
    this.#check(len);
    const data = this.#data.slice(this.#offset, this.#offset + len);
    this.#offset += len;
    return data;
  }

  readStringAsUTF8(): string {
    return utf8Decode(this.readString());
  }

  readMpint(): bigint {
    const bytes = this.readString();
    if (bytes.length === 0) return 0n;

    const negative = (bytes[0] & 0x80) !== 0;

    if (negative) {
      // Two's complement negative
      // Invert bits, convert to positive, negate
      const inverted = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        inverted[i] = ~bytes[i] & 0xff;
      }
      // Add 1 to inverted
      let carry = 1;
      for (let i = inverted.length - 1; i >= 0 && carry; i--) {
        const sum = inverted[i] + carry;
        inverted[i] = sum & 0xff;
        carry = sum >> 8;
      }
      let val = 0n;
      for (const b of inverted) {
        val = (val << 8n) | BigInt(b);
      }
      return -val;
    } else {
      let val = 0n;
      for (const b of bytes) {
        val = (val << 8n) | BigInt(b);
      }
      return val;
    }
  }

  readNameList(): string[] {
    const s = this.readStringAsUTF8();
    if (s.length === 0) return [];
    return s.split(",");
  }

  readBytes(n: number): Uint8Array {
    this.#check(n);
    const data = this.#data.slice(this.#offset, this.#offset + n);
    this.#offset += n;
    return data;
  }

  remaining(): number {
    return this.#data.length - this.#offset;
  }

  position(): number {
    return this.#offset;
  }

  rest(): Uint8Array {
    return this.#data.slice(this.#offset);
  }
}
