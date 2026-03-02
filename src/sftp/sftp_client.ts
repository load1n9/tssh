import type { Channel } from "../connection/channel.ts";
import { concatBytes } from "../utils/encoding.ts";
import { SFTPError } from "../utils/errors.ts";
import * as SC from "./sftp_constants.ts";
import { SftpPacketReader, SftpPacketWriter } from "./sftp_packet.ts";
import {
  FileAttributes,
  type SftpDirectoryEntry,
  SftpHandle,
} from "./sftp_types.ts";

export class SftpClient {
  #nextRequestId = 1;
  #pendingRequests = new Map<
    number,
    {
      resolve: (reader: SftpPacketReader) => void;
      reject: (err: Error) => void;
    }
  >();
  #readBuffer: Uint8Array = new Uint8Array(0);
  #version = 0;
  #channel: Channel;

  constructor(channel: Channel) {
    this.#channel = channel;
    this.#startReadLoop();
  }

  #startReadLoop(): void {
    (async () => {
      try {
        for await (const chunk of this.#channel.readData()) {
          this.#readBuffer = concatBytes(this.#readBuffer, chunk);
          this.#processBuffer();
        }
      } catch (_) {
        // Channel closed
      }
      // Close all pending requests
      for (const [, pending] of this.#pendingRequests) {
        pending.reject(
          new SFTPError("SFTP connection closed", SC.SSH_FX_CONNECTION_LOST),
        );
      }
      this.#pendingRequests.clear();
    })();
  }

  #processBuffer(): void {
    while (this.#readBuffer.length >= 4) {
      const view = new DataView(
        this.#readBuffer.buffer,
        this.#readBuffer.byteOffset,
        4,
      );
      const packetLen = view.getUint32(0);
      if (this.#readBuffer.length < 4 + packetLen) break;

      const payload = this.#readBuffer.slice(4, 4 + packetLen);
      this.#readBuffer = this.#readBuffer.slice(4 + packetLen);

      const reader = new SftpPacketReader(payload);
      const type = reader.readUint8();

      if (type === SC.SSH_FXP_VERSION) {
        this.#version = reader.readUint32();
        continue;
      }

      const requestId = reader.readUint32();
      const pending = this.#pendingRequests.get(requestId);
      if (pending) {
        this.#pendingRequests.delete(requestId);
        // Reset reader so caller sees type + requestId already consumed,
        // but provide a new reader starting after type + requestId
        const responsePayload = payload.slice(5); // skip type(1) + requestId(4)
        pending.resolve(
          new SftpPacketReader(
            // Reconstruct: first byte = type, then the rest
            concatBytes(
              new Uint8Array([type]),
              new Uint8Array(4),
              responsePayload,
            ),
          ),
        );
      }
    }
  }

  async #sendRequest(
    type: number,
    build: (w: SftpPacketWriter) => void,
  ): Promise<SftpPacketReader> {
    const requestId = this.#nextRequestId++;
    const w = new SftpPacketWriter(256);
    w.writeUint8(type);
    w.writeUint32(requestId);
    build(w);
    const packet = w.toPacket();
    await this.#channel.write(packet);

    return new Promise((resolve, reject) => {
      this.#pendingRequests.set(requestId, { resolve, reject });
    });
  }

  #checkStatus(
    reader: SftpPacketReader,
    okStatuses: number[] = [SC.SSH_FX_OK],
  ): void {
    if (reader.type === SC.SSH_FXP_STATUS) {
      reader.readUint8(); // skip type
      reader.readUint32(); // skip request id
      const code = reader.readUint32();
      const message = reader.remaining >= 4 ? reader.readString() : "";
      if (!okStatuses.includes(code)) {
        throw new SFTPError(message || `SFTP error code ${code}`, code);
      }
    }
  }

  async initialize(): Promise<number> {
    const w = new SftpPacketWriter(16);
    w.writeUint8(SC.SSH_FXP_INIT);
    w.writeUint32(SC.SFTP_VERSION);
    await this.#channel.write(w.toPacket());

    // Wait for VERSION response
    await new Promise<void>((resolve) => {
      const check = () => {
        if (this.#version > 0) resolve();
        else setTimeout(check, 10);
      };
      check();
    });
    return this.#version;
  }

  async open(
    path: string,
    flags: number,
    attrs?: FileAttributes,
  ): Promise<SftpHandle> {
    const reader = await this.#sendRequest(SC.SSH_FXP_OPEN, (w) => {
      w.writeString(path);
      w.writeUint32(flags);
      w.writeAttrs(attrs ?? new FileAttributes());
    });

    if (reader.type === SC.SSH_FXP_HANDLE) {
      reader.readUint8();
      reader.readUint32();
      return new SftpHandle(reader.readBuffer());
    }
    this.#checkStatus(reader);
    throw new SFTPError("Unexpected response to open", SC.SSH_FX_FAILURE);
  }

  async close(handle: SftpHandle): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_CLOSE, (w) => {
      w.writeBuffer(handle.rawHandle);
    });
    this.#checkStatus(reader);
  }

  async read(
    handle: SftpHandle,
    offset: bigint,
    length: number,
  ): Promise<Uint8Array | null> {
    const reader = await this.#sendRequest(SC.SSH_FXP_READ, (w) => {
      w.writeBuffer(handle.rawHandle);
      w.writeUint64(offset);
      w.writeUint32(length);
    });

    if (reader.type === SC.SSH_FXP_DATA) {
      reader.readUint8();
      reader.readUint32();
      return reader.readBuffer();
    }
    if (reader.type === SC.SSH_FXP_STATUS) {
      reader.readUint8();
      reader.readUint32();
      const code = reader.readUint32();
      if (code === SC.SSH_FX_EOF) return null;
      const message = reader.remaining >= 4 ? reader.readString() : "";
      throw new SFTPError(message, code);
    }
    throw new SFTPError("Unexpected response to read", SC.SSH_FX_FAILURE);
  }

  async write(
    handle: SftpHandle,
    offset: bigint,
    data: Uint8Array,
  ): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_WRITE, (w) => {
      w.writeBuffer(handle.rawHandle);
      w.writeUint64(offset);
      w.writeBuffer(data);
    });
    this.#checkStatus(reader);
  }

  async stat(path: string): Promise<FileAttributes> {
    const reader = await this.#sendRequest(SC.SSH_FXP_STAT, (w) => {
      w.writeString(path);
    });
    if (reader.type === SC.SSH_FXP_ATTRS) {
      reader.readUint8();
      reader.readUint32();
      return reader.readAttrs();
    }
    this.#checkStatus(reader);
    throw new SFTPError("Unexpected response to stat", SC.SSH_FX_FAILURE);
  }

  async lstat(path: string): Promise<FileAttributes> {
    const reader = await this.#sendRequest(SC.SSH_FXP_LSTAT, (w) => {
      w.writeString(path);
    });
    if (reader.type === SC.SSH_FXP_ATTRS) {
      reader.readUint8();
      reader.readUint32();
      return reader.readAttrs();
    }
    this.#checkStatus(reader);
    throw new SFTPError("Unexpected response to lstat", SC.SSH_FX_FAILURE);
  }

  async fstat(handle: SftpHandle): Promise<FileAttributes> {
    const reader = await this.#sendRequest(SC.SSH_FXP_FSTAT, (w) => {
      w.writeBuffer(handle.rawHandle);
    });
    if (reader.type === SC.SSH_FXP_ATTRS) {
      reader.readUint8();
      reader.readUint32();
      return reader.readAttrs();
    }
    this.#checkStatus(reader);
    throw new SFTPError("Unexpected response to fstat", SC.SSH_FX_FAILURE);
  }

  async setstat(path: string, attrs: FileAttributes): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_SETSTAT, (w) => {
      w.writeString(path);
      w.writeAttrs(attrs);
    });
    this.#checkStatus(reader);
  }

  async fsetstat(handle: SftpHandle, attrs: FileAttributes): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_FSETSTAT, (w) => {
      w.writeBuffer(handle.rawHandle);
      w.writeAttrs(attrs);
    });
    this.#checkStatus(reader);
  }

  async opendir(path: string): Promise<SftpHandle> {
    const reader = await this.#sendRequest(SC.SSH_FXP_OPENDIR, (w) => {
      w.writeString(path);
    });
    if (reader.type === SC.SSH_FXP_HANDLE) {
      reader.readUint8();
      reader.readUint32();
      return new SftpHandle(reader.readBuffer());
    }
    this.#checkStatus(reader);
    throw new SFTPError("Unexpected response to opendir", SC.SSH_FX_FAILURE);
  }

  async readdir(handle: SftpHandle): Promise<SftpDirectoryEntry[]> {
    const reader = await this.#sendRequest(SC.SSH_FXP_READDIR, (w) => {
      w.writeBuffer(handle.rawHandle);
    });
    if (reader.type === SC.SSH_FXP_NAME) {
      reader.readUint8();
      reader.readUint32();
      const count = reader.readUint32();
      const entries: SftpDirectoryEntry[] = [];
      for (let i = 0; i < count; i++) {
        entries.push({
          filename: reader.readString(),
          longname: reader.readString(),
          attrs: reader.readAttrs(),
        });
      }
      return entries;
    }
    if (reader.type === SC.SSH_FXP_STATUS) {
      reader.readUint8();
      reader.readUint32();
      const code = reader.readUint32();
      if (code === SC.SSH_FX_EOF) return [];
      const message = reader.remaining >= 4 ? reader.readString() : "";
      throw new SFTPError(message, code);
    }
    throw new SFTPError("Unexpected response to readdir", SC.SSH_FX_FAILURE);
  }

  async remove(path: string): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_REMOVE, (w) => {
      w.writeString(path);
    });
    this.#checkStatus(reader);
  }

  async rename(oldPath: string, newPath: string): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_RENAME, (w) => {
      w.writeString(oldPath);
      w.writeString(newPath);
    });
    this.#checkStatus(reader);
  }

  async mkdir(path: string, attrs?: FileAttributes): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_MKDIR, (w) => {
      w.writeString(path);
      w.writeAttrs(attrs ?? new FileAttributes());
    });
    this.#checkStatus(reader);
  }

  async rmdir(path: string): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_RMDIR, (w) => {
      w.writeString(path);
    });
    this.#checkStatus(reader);
  }

  async realpath(path: string): Promise<string> {
    const reader = await this.#sendRequest(SC.SSH_FXP_REALPATH, (w) => {
      w.writeString(path);
    });
    if (reader.type === SC.SSH_FXP_NAME) {
      reader.readUint8();
      reader.readUint32();
      const count = reader.readUint32();
      if (count >= 1) return reader.readString();
    }
    this.#checkStatus(reader);
    throw new SFTPError("Unexpected response to realpath", SC.SSH_FX_FAILURE);
  }

  async readlink(path: string): Promise<string> {
    const reader = await this.#sendRequest(SC.SSH_FXP_READLINK, (w) => {
      w.writeString(path);
    });
    if (reader.type === SC.SSH_FXP_NAME) {
      reader.readUint8();
      reader.readUint32();
      const count = reader.readUint32();
      if (count >= 1) return reader.readString();
    }
    this.#checkStatus(reader);
    throw new SFTPError("Unexpected response to readlink", SC.SSH_FX_FAILURE);
  }

  async symlink(linkPath: string, targetPath: string): Promise<void> {
    const reader = await this.#sendRequest(SC.SSH_FXP_SYMLINK, (w) => {
      w.writeString(targetPath);
      w.writeString(linkPath);
    });
    this.#checkStatus(reader);
  }

  async readFile(remotePath: string): Promise<Uint8Array> {
    const handle = await this.open(remotePath, SC.SSH_FXF_READ);
    try {
      const chunks: Uint8Array[] = [];
      let offset = 0n;
      while (true) {
        const data = await this.read(handle, offset, 32768);
        if (data === null) break;
        chunks.push(data);
        offset += BigInt(data.length);
      }
      return concatBytes(...chunks);
    } finally {
      await this.close(handle);
    }
  }

  async writeFile(remotePath: string, data: Uint8Array): Promise<void> {
    const handle = await this.open(
      remotePath,
      SC.SSH_FXF_WRITE | SC.SSH_FXF_CREAT | SC.SSH_FXF_TRUNC,
    );
    try {
      let offset = 0n;
      while (offset < BigInt(data.length)) {
        const chunk = data.subarray(Number(offset), Number(offset) + 32768);
        await this.write(handle, offset, chunk);
        offset += BigInt(chunk.length);
      }
    } finally {
      await this.close(handle);
    }
  }

  async exists(path: string): Promise<boolean> {
    try {
      await this.stat(path);
      return true;
    } catch (e) {
      if (e instanceof SFTPError && e.statusCode === SC.SSH_FX_NO_SUCH_FILE) {
        return false;
      }
      throw e;
    }
  }

  async *listDir(path: string): AsyncIterableIterator<SftpDirectoryEntry> {
    const handle = await this.opendir(path);
    try {
      while (true) {
        const entries = await this.readdir(handle);
        if (entries.length === 0) break;
        for (const entry of entries) {
          if (entry.filename !== "." && entry.filename !== "..") {
            yield entry;
          }
        }
      }
    } finally {
      await this.close(handle);
    }
  }

  async end(): Promise<void> {
    await this.#channel.sendEof();
    await this.#channel.close();
  }
}
