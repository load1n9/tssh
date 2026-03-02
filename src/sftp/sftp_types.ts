import { hexEncode } from "../utils/encoding.ts";
import * as SC from "./sftp_constants.ts";

export class FileAttributes {
  size?: bigint;
  uid?: number;
  gid?: number;
  permissions?: number;
  atime?: number;
  mtime?: number;
  extended?: Map<string, string>;

  constructor(init?: Partial<FileAttributes>) {
    if (init) Object.assign(this, init);
  }

  get flags(): number {
    let f = 0;
    if (this.size !== undefined) f |= SC.SSH_FILEXFER_ATTR_SIZE;
    if (this.uid !== undefined && this.gid !== undefined) {
      f |= SC.SSH_FILEXFER_ATTR_UIDGID;
    }
    if (this.permissions !== undefined) f |= SC.SSH_FILEXFER_ATTR_PERMISSIONS;
    if (this.atime !== undefined && this.mtime !== undefined) {
      f |= SC.SSH_FILEXFER_ATTR_ACMODTIME;
    }
    if (this.extended && this.extended.size > 0) {
      f |= SC.SSH_FILEXFER_ATTR_EXTENDED;
    }
    return f;
  }

  isDirectory(): boolean {
    return this.permissions !== undefined && (this.permissions & 0o40000) !== 0;
  }

  isFile(): boolean {
    return this.permissions !== undefined &&
      (this.permissions & 0o100000) !== 0;
  }

  isSymlink(): boolean {
    return this.permissions !== undefined &&
      (this.permissions & 0o120000) !== 0;
  }
}

export class SftpHandle {
  constructor(public readonly rawHandle: Uint8Array) {}

  get id(): string {
    return hexEncode(this.rawHandle);
  }
}

export interface SftpDirectoryEntry {
  filename: string;
  longname: string;
  attrs: FileAttributes;
}
