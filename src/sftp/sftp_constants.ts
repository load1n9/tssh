// SFTP Packet Types
export const SSH_FXP_INIT = 1;
export const SSH_FXP_VERSION = 2;
export const SSH_FXP_OPEN = 3;
export const SSH_FXP_CLOSE = 4;
export const SSH_FXP_READ = 5;
export const SSH_FXP_WRITE = 6;
export const SSH_FXP_LSTAT = 7;
export const SSH_FXP_FSTAT = 8;
export const SSH_FXP_SETSTAT = 9;
export const SSH_FXP_FSETSTAT = 10;
export const SSH_FXP_OPENDIR = 11;
export const SSH_FXP_READDIR = 12;
export const SSH_FXP_REMOVE = 13;
export const SSH_FXP_MKDIR = 14;
export const SSH_FXP_RMDIR = 15;
export const SSH_FXP_REALPATH = 16;
export const SSH_FXP_STAT = 17;
export const SSH_FXP_RENAME = 18;
export const SSH_FXP_READLINK = 19;
export const SSH_FXP_SYMLINK = 20;
export const SSH_FXP_STATUS = 101;
export const SSH_FXP_HANDLE = 102;
export const SSH_FXP_DATA = 103;
export const SSH_FXP_NAME = 104;
export const SSH_FXP_ATTRS = 105;
export const SSH_FXP_EXTENDED = 200;
export const SSH_FXP_EXTENDED_REPLY = 201;

// Status Codes
export const SSH_FX_OK = 0;
export const SSH_FX_EOF = 1;
export const SSH_FX_NO_SUCH_FILE = 2;
export const SSH_FX_PERMISSION_DENIED = 3;
export const SSH_FX_FAILURE = 4;
export const SSH_FX_BAD_MESSAGE = 5;
export const SSH_FX_NO_CONNECTION = 6;
export const SSH_FX_CONNECTION_LOST = 7;
export const SSH_FX_OP_UNSUPPORTED = 8;

// Open Flags (pflags)
export const SSH_FXF_READ = 0x00000001;
export const SSH_FXF_WRITE = 0x00000002;
export const SSH_FXF_APPEND = 0x00000004;
export const SSH_FXF_CREAT = 0x00000008;
export const SSH_FXF_TRUNC = 0x00000010;
export const SSH_FXF_EXCL = 0x00000020;

// Attribute Flags
export const SSH_FILEXFER_ATTR_SIZE = 0x00000001;
export const SSH_FILEXFER_ATTR_UIDGID = 0x00000002;
export const SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
export const SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008;
export const SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;

// SFTP Protocol Version
export const SFTP_VERSION = 3;
