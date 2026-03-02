import { utf8Decode, utf8Encode } from "../utils/encoding.ts";
import * as SC from "./sftp_constants.ts";
import { FileAttributes } from "./sftp_types.ts";

export class SftpPacketWriter {
  #buf: Uint8Array;
  #view: DataView;
  #offset = 0;

  constructor(initialCapacity = 256) {
    this.#buf = new Uint8Array(initialCapacity);
    this.#view = new DataView(this.#buf.buffer);
  }

  #ensure(n: number): void {
    const needed = this.#offset + n;
    if (needed <= this.#buf.length) return;
    let newSize = this.#buf.length * 2;
    while (newSize < needed) newSize *= 2;
    const newBuf = new Uint8Array(newSize);
    newBuf.set(this.#buf);
    this.#buf = newBuf;
    this.#view = new DataView(this.#buf.buffer);
  }

  writeUint8(v: number): this {
    this.#ensure(1);
    this.#buf[this.#offset++] = v & 0xff;
    return this;
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

  writeString(s: string): this {
    const bytes = utf8Encode(s);
    this.writeUint32(bytes.length);
    this.writeRaw(bytes);
    return this;
  }

  writeBuffer(data: Uint8Array): this {
    this.writeUint32(data.length);
    this.writeRaw(data);
    return this;
  }

  writeRaw(data: Uint8Array): this {
    this.#ensure(data.length);
    this.#buf.set(data, this.#offset);
    this.#offset += data.length;
    return this;
  }

  writeAttrs(attrs: FileAttributes): this {
    const flags = attrs.flags;
    this.writeUint32(flags);
    if (flags & SC.SSH_FILEXFER_ATTR_SIZE) this.writeUint64(attrs.size!);
    if (flags & SC.SSH_FILEXFER_ATTR_UIDGID) {
      this.writeUint32(attrs.uid!);
      this.writeUint32(attrs.gid!);
    }
    if (flags & SC.SSH_FILEXFER_ATTR_PERMISSIONS) {
      this.writeUint32(attrs.permissions!);
    }
    if (flags & SC.SSH_FILEXFER_ATTR_ACMODTIME) {
      this.writeUint32(attrs.atime!);
      this.writeUint32(attrs.mtime!);
    }
    if (flags & SC.SSH_FILEXFER_ATTR_EXTENDED) {
      const ext = attrs.extended!;
      this.writeUint32(ext.size);
      for (const [key, val] of ext) {
        this.writeString(key);
        this.writeString(val);
      }
    }
    return this;
  }

  /** Finalize: prepend uint32 length, return complete SFTP packet */
  toPacket(): Uint8Array {
    const payload = this.#buf.slice(0, this.#offset);
    const packet = new Uint8Array(4 + payload.length);
    new DataView(packet.buffer).setUint32(0, payload.length);
    packet.set(payload, 4);
    return packet;
  }

  /** Get raw bytes without length prefix */
  toBytes(): Uint8Array {
    return this.#buf.slice(0, this.#offset);
  }
}

export class SftpPacketReader {
  #view: DataView;
  #offset = 0;

  constructor(private data: Uint8Array) {
    this.#view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  get type(): number {
    return this.data[0];
  }

  readUint8(): number {
    return this.data[this.#offset++];
  }

  readUint32(): number {
    const v = this.#view.getUint32(this.#offset);
    this.#offset += 4;
    return v;
  }

  readUint64(): bigint {
    const v = this.#view.getBigUint64(this.#offset);
    this.#offset += 8;
    return v;
  }

  readString(): string {
    const len = this.readUint32();
    const bytes = this.data.slice(this.#offset, this.#offset + len);
    this.#offset += len;
    return utf8Decode(bytes);
  }

  readBuffer(): Uint8Array {
    const len = this.readUint32();
    const bytes = this.data.slice(this.#offset, this.#offset + len);
    this.#offset += len;
    return bytes;
  }

  readAttrs(): FileAttributes {
    const flags = this.readUint32();
    const attrs = new FileAttributes();
    if (flags & SC.SSH_FILEXFER_ATTR_SIZE) attrs.size = this.readUint64();
    if (flags & SC.SSH_FILEXFER_ATTR_UIDGID) {
      attrs.uid = this.readUint32();
      attrs.gid = this.readUint32();
    }
    if (flags & SC.SSH_FILEXFER_ATTR_PERMISSIONS) {
      attrs.permissions = this.readUint32();
    }
    if (flags & SC.SSH_FILEXFER_ATTR_ACMODTIME) {
      attrs.atime = this.readUint32();
      attrs.mtime = this.readUint32();
    }
    if (flags & SC.SSH_FILEXFER_ATTR_EXTENDED) {
      const count = this.readUint32();
      attrs.extended = new Map();
      for (let i = 0; i < count; i++) {
        const key = this.readString();
        const val = this.readString();
        attrs.extended.set(key, val);
      }
    }
    return attrs;
  }

  get remaining(): number {
    return this.data.length - this.#offset;
  }
}
