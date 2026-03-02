import type { Channel } from "../connection/channel.ts";
import { concatBytes } from "../utils/encoding.ts";
import { hexEncode } from "../utils/encoding.ts";
import { SFTPError } from "../utils/errors.ts";
import * as SC from "./sftp_constants.ts";
import { SftpPacketReader, SftpPacketWriter } from "./sftp_packet.ts";
import { FileAttributes, type SftpDirectoryEntry } from "./sftp_types.ts";

interface OpenFileState {
  kind: "file";
  file: Deno.FsFile;
  path: string;
  flags: number;
}

interface OpenDirState {
  kind: "directory";
  path: string;
  entries: Deno.DirEntry[];
  position: number;
}

type HandleState = OpenFileState | OpenDirState;

export class SftpServer {
  #handles = new Map<string, HandleState>();
  #handleCounter = 0;
  #readBuffer: Uint8Array = new Uint8Array(0);
  #channel: Channel;
  #rootPath = Deno.cwd();

  constructor(channel: Channel, rootPath: string = Deno.cwd()) {
    this.#channel = channel;
    this.#rootPath = rootPath;
  }

  async serve(): Promise<void> {
    // Wait for INIT
    for await (const chunk of this.#channel.readData()) {
      this.#readBuffer = concatBytes(this.#readBuffer, chunk);
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

        if (type === SC.SSH_FXP_INIT) {
          const _clientVersion = reader.readUint32();
          await this.#sendVersion();
          continue;
        }

        const requestId = reader.readUint32();
        await this.#handleRequest(type, requestId, reader);
      }
    }

    // Cleanup all open handles
    await this.#closeAllHandles();
  }

  async #sendVersion(): Promise<void> {
    const w = new SftpPacketWriter(16);
    w.writeUint8(SC.SSH_FXP_VERSION);
    w.writeUint32(SC.SFTP_VERSION);
    await this.#channel.write(w.toPacket());
  }

  async #handleRequest(
    type: number,
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    try {
      switch (type) {
        case SC.SSH_FXP_OPEN:
          await this.#handleOpen(requestId, reader);
          break;
        case SC.SSH_FXP_CLOSE:
          await this.#handleClose(requestId, reader);
          break;
        case SC.SSH_FXP_READ:
          await this.#handleRead(requestId, reader);
          break;
        case SC.SSH_FXP_WRITE:
          await this.#handleWrite(requestId, reader);
          break;
        case SC.SSH_FXP_STAT:
          await this.#handleStat(requestId, reader);
          break;
        case SC.SSH_FXP_LSTAT:
          await this.#handleLstat(requestId, reader);
          break;
        case SC.SSH_FXP_FSTAT:
          await this.#handleFstat(requestId, reader);
          break;
        case SC.SSH_FXP_SETSTAT:
          await this.#handleSetstat(requestId, reader);
          break;
        case SC.SSH_FXP_OPENDIR:
          await this.#handleOpendir(requestId, reader);
          break;
        case SC.SSH_FXP_READDIR:
          await this.#handleReaddir(requestId, reader);
          break;
        case SC.SSH_FXP_REMOVE:
          await this.#handleRemove(requestId, reader);
          break;
        case SC.SSH_FXP_RENAME:
          await this.#handleRename(requestId, reader);
          break;
        case SC.SSH_FXP_MKDIR:
          await this.#handleMkdir(requestId, reader);
          break;
        case SC.SSH_FXP_RMDIR:
          await this.#handleRmdir(requestId, reader);
          break;
        case SC.SSH_FXP_REALPATH:
          await this.#handleRealpath(requestId, reader);
          break;
        case SC.SSH_FXP_READLINK:
          await this.#handleReadlink(requestId, reader);
          break;
        case SC.SSH_FXP_SYMLINK:
          await this.#handleSymlink(requestId, reader);
          break;
        default:
          await this.#sendStatus(
            requestId,
            SC.SSH_FX_OP_UNSUPPORTED,
            "Unknown request",
          );
      }
    } catch (err) {
      const code = this.#mapErrorToStatusCode(err);
      const message = err instanceof Error ? err.message : String(err);
      await this.#sendStatus(requestId, code, message);
    }
  }

  #allocateHandle(): Uint8Array {
    const id = this.#handleCounter++;
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, id);
    return buf;
  }

  #getFileState(handle: Uint8Array): OpenFileState {
    const state = this.#handles.get(hexEncode(handle));
    if (!state || state.kind !== "file") {
      throw new SFTPError("Invalid file handle", SC.SSH_FX_FAILURE);
    }
    return state;
  }

  #getDirState(handle: Uint8Array): OpenDirState {
    const state = this.#handles.get(hexEncode(handle));
    if (!state || state.kind !== "directory") {
      throw new SFTPError("Invalid directory handle", SC.SSH_FX_FAILURE);
    }
    return state;
  }

  #resolvePath(path: string): string {
    if (path.startsWith("/")) return path;
    return `${this.#rootPath}/${path}`;
  }

  async #handleOpen(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    const pflags = reader.readUint32();
    const _attrs = reader.readAttrs();

    const resolved = this.#resolvePath(path);
    const options: Deno.OpenOptions = {
      read: (pflags & SC.SSH_FXF_READ) !== 0,
      write: (pflags & SC.SSH_FXF_WRITE) !== 0,
      append: (pflags & SC.SSH_FXF_APPEND) !== 0,
      create: (pflags & SC.SSH_FXF_CREAT) !== 0,
      truncate: (pflags & SC.SSH_FXF_TRUNC) !== 0,
      createNew: (pflags & SC.SSH_FXF_EXCL) !== 0,
    };

    const file = await Deno.open(resolved, options);
    const handle = this.#allocateHandle();
    this.#handles.set(hexEncode(handle), {
      kind: "file",
      file,
      path: resolved,
      flags: pflags,
    });
    await this.#sendHandle(requestId, handle);
  }

  async #handleClose(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const handle = reader.readBuffer();
    const key = hexEncode(handle);
    const state = this.#handles.get(key);
    if (state) {
      if (state.kind === "file") state.file.close();
      this.#handles.delete(key);
    }
    await this.#sendStatus(requestId, SC.SSH_FX_OK, "");
  }

  async #handleRead(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const handle = reader.readBuffer();
    const offset = reader.readUint64();
    const length = reader.readUint32();

    const state = this.#getFileState(handle);
    await state.file.seek(Number(offset), Deno.SeekMode.Start);
    const buf = new Uint8Array(length);
    const bytesRead = await state.file.read(buf);

    if (bytesRead === null || bytesRead === 0) {
      await this.#sendStatus(requestId, SC.SSH_FX_EOF, "");
      return;
    }

    await this.#sendData(requestId, buf.subarray(0, bytesRead));
  }

  async #handleWrite(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const handle = reader.readBuffer();
    const offset = reader.readUint64();
    const data = reader.readBuffer();

    const state = this.#getFileState(handle);
    await state.file.seek(Number(offset), Deno.SeekMode.Start);
    let written = 0;
    while (written < data.length) {
      written += await state.file.write(data.subarray(written));
    }

    await this.#sendStatus(requestId, SC.SSH_FX_OK, "");
  }

  async #handleStat(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    const info = await Deno.stat(this.#resolvePath(path));
    await this.#sendAttrs(requestId, this.#fileInfoToAttrs(info));
  }

  async #handleLstat(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    const info = await Deno.lstat(this.#resolvePath(path));
    await this.#sendAttrs(requestId, this.#fileInfoToAttrs(info));
  }

  async #handleFstat(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const handle = reader.readBuffer();
    const state = this.#getFileState(handle);
    const info = await state.file.stat();
    await this.#sendAttrs(requestId, this.#fileInfoToAttrs(info));
  }

  async #handleSetstat(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    const attrs = reader.readAttrs();
    const resolved = this.#resolvePath(path);

    if (attrs.permissions !== undefined) {
      await Deno.chmod(resolved, attrs.permissions);
    }
    if (attrs.atime !== undefined && attrs.mtime !== undefined) {
      await Deno.utime(resolved, attrs.atime, attrs.mtime);
    }

    await this.#sendStatus(requestId, SC.SSH_FX_OK, "");
  }

  async #handleOpendir(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    const resolved = this.#resolvePath(path);
    const entries: Deno.DirEntry[] = [];
    for await (const entry of Deno.readDir(resolved)) {
      entries.push(entry);
    }

    const handle = this.#allocateHandle();
    this.#handles.set(hexEncode(handle), {
      kind: "directory",
      path: resolved,
      entries,
      position: 0,
    });
    await this.#sendHandle(requestId, handle);
  }

  async #handleReaddir(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const handle = reader.readBuffer();
    const state = this.#getDirState(handle);

    if (state.position >= state.entries.length) {
      await this.#sendStatus(requestId, SC.SSH_FX_EOF, "");
      return;
    }

    const batchSize = 64;
    const batch = state.entries.slice(
      state.position,
      state.position + batchSize,
    );
    state.position += batch.length;

    const sftpEntries: SftpDirectoryEntry[] = [];
    for (const entry of batch) {
      try {
        const fullPath = `${state.path}/${entry.name}`;
        const info = await Deno.stat(fullPath);
        sftpEntries.push({
          filename: entry.name,
          longname: entry.name, // simplified
          attrs: this.#fileInfoToAttrs(info),
        });
      } catch (_) {
        sftpEntries.push({
          filename: entry.name,
          longname: entry.name,
          attrs: new FileAttributes(),
        });
      }
    }

    await this.#sendName(requestId, sftpEntries);
  }

  async #handleRemove(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    await Deno.remove(this.#resolvePath(path));
    await this.#sendStatus(requestId, SC.SSH_FX_OK, "");
  }

  async #handleRename(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const oldPath = reader.readString();
    const newPath = reader.readString();
    await Deno.rename(this.#resolvePath(oldPath), this.#resolvePath(newPath));
    await this.#sendStatus(requestId, SC.SSH_FX_OK, "");
  }

  async #handleMkdir(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    const _attrs = reader.readAttrs();
    await Deno.mkdir(this.#resolvePath(path), { recursive: false });
    await this.#sendStatus(requestId, SC.SSH_FX_OK, "");
  }

  async #handleRmdir(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    await Deno.remove(this.#resolvePath(path));
    await this.#sendStatus(requestId, SC.SSH_FX_OK, "");
  }

  async #handleRealpath(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    const resolved = await Deno.realPath(this.#resolvePath(path));
    await this.#sendName(requestId, [
      {
        filename: resolved,
        longname: resolved,
        attrs: new FileAttributes(),
      },
    ]);
  }

  async #handleReadlink(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const path = reader.readString();
    const target = await Deno.readLink(this.#resolvePath(path));
    await this.#sendName(requestId, [
      {
        filename: target,
        longname: target,
        attrs: new FileAttributes(),
      },
    ]);
  }

  async #handleSymlink(
    requestId: number,
    reader: SftpPacketReader,
  ): Promise<void> {
    const targetPath = reader.readString();
    const linkPath = reader.readString();
    await Deno.symlink(
      this.#resolvePath(targetPath),
      this.#resolvePath(linkPath),
    );
    await this.#sendStatus(requestId, SC.SSH_FX_OK, "");
  }

  async #sendStatus(
    requestId: number,
    code: number,
    message: string,
  ): Promise<void> {
    const w = new SftpPacketWriter(64);
    w.writeUint8(SC.SSH_FXP_STATUS);
    w.writeUint32(requestId);
    w.writeUint32(code);
    w.writeString(message);
    w.writeString("en");
    await this.#channel.write(w.toPacket());
  }

  async #sendHandle(requestId: number, handle: Uint8Array): Promise<void> {
    const w = new SftpPacketWriter(32);
    w.writeUint8(SC.SSH_FXP_HANDLE);
    w.writeUint32(requestId);
    w.writeBuffer(handle);
    await this.#channel.write(w.toPacket());
  }

  async #sendData(requestId: number, data: Uint8Array): Promise<void> {
    const w = new SftpPacketWriter(data.length + 16);
    w.writeUint8(SC.SSH_FXP_DATA);
    w.writeUint32(requestId);
    w.writeBuffer(data);
    await this.#channel.write(w.toPacket());
  }

  async #sendAttrs(requestId: number, attrs: FileAttributes): Promise<void> {
    const w = new SftpPacketWriter(64);
    w.writeUint8(SC.SSH_FXP_ATTRS);
    w.writeUint32(requestId);
    w.writeAttrs(attrs);
    await this.#channel.write(w.toPacket());
  }

  async #sendName(
    requestId: number,
    entries: SftpDirectoryEntry[],
  ): Promise<void> {
    const w = new SftpPacketWriter(256);
    w.writeUint8(SC.SSH_FXP_NAME);
    w.writeUint32(requestId);
    w.writeUint32(entries.length);
    for (const entry of entries) {
      w.writeString(entry.filename);
      w.writeString(entry.longname);
      w.writeAttrs(entry.attrs);
    }
    await this.#channel.write(w.toPacket());
  }

  #fileInfoToAttrs(info: Deno.FileInfo): FileAttributes {
    const attrs = new FileAttributes();
    if (info.size !== null) attrs.size = BigInt(info.size);
    if (info.mode !== null) attrs.permissions = info.mode;
    if (info.atime) attrs.atime = Math.floor(info.atime.getTime() / 1000);
    if (info.mtime) attrs.mtime = Math.floor(info.mtime.getTime() / 1000);
    return attrs;
  }

  #mapErrorToStatusCode(err: unknown): number {
    if (err instanceof Deno.errors.NotFound) return SC.SSH_FX_NO_SUCH_FILE;
    if (err instanceof Deno.errors.PermissionDenied) {
      return SC.SSH_FX_PERMISSION_DENIED;
    }
    if (err instanceof SFTPError) return err.statusCode;
    return SC.SSH_FX_FAILURE;
  }

  // deno-lint-ignore require-await
  async #closeAllHandles(): Promise<void> {
    for (const [key, state] of this.#handles) {
      if (state.kind === "file") {
        try {
          state.file.close();
        } catch (_) {
          /* ignore */
        }
      }
      this.#handles.delete(key);
    }
  }
}
