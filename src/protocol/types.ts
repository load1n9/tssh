// SSH wire format type aliases (RFC 4251 Section 5)
// These are documentation types - they don't enforce at runtime,
// but clarify intent in function signatures.

/** A single byte (0-255) */
export type SSHByte = number;

/** Boolean: 0 = false, non-zero = true */
export type SSHBoolean = boolean;

/** 32-bit unsigned integer, network byte order */
export type SSHUint32 = number;

/** 64-bit unsigned integer, network byte order */
export type SSHUint64 = bigint;

/** Variable-length byte string (uint32 length prefix + data) */
export type SSHString = Uint8Array;

/** Multiple precision integer in two's complement, big-endian */
export type SSHMpint = bigint;

/** Comma-separated list of ASCII names */
export type SSHNameList = string[];
