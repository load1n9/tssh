// SSH Message Numbers (RFC 4253, 4252, 4254)
export const SSH_MSG_DISCONNECT = 1;
export const SSH_MSG_IGNORE = 2;
export const SSH_MSG_UNIMPLEMENTED = 3;
export const SSH_MSG_DEBUG = 4;
export const SSH_MSG_SERVICE_REQUEST = 5;
export const SSH_MSG_SERVICE_ACCEPT = 6;

export const SSH_MSG_KEXINIT = 20;
export const SSH_MSG_NEWKEYS = 21;

// Key exchange method-specific (curve25519-sha256 reuses ECDH messages)
export const SSH_MSG_KEX_ECDH_INIT = 30;
export const SSH_MSG_KEX_ECDH_REPLY = 31;

// Authentication (RFC 4252)
export const SSH_MSG_USERAUTH_REQUEST = 50;
export const SSH_MSG_USERAUTH_FAILURE = 51;
export const SSH_MSG_USERAUTH_SUCCESS = 52;
export const SSH_MSG_USERAUTH_BANNER = 53;
export const SSH_MSG_USERAUTH_PK_OK = 60;

// Connection protocol (RFC 4254)
export const SSH_MSG_GLOBAL_REQUEST = 80;
export const SSH_MSG_REQUEST_SUCCESS = 81;
export const SSH_MSG_REQUEST_FAILURE = 82;
export const SSH_MSG_CHANNEL_OPEN = 90;
export const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
export const SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
export const SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
export const SSH_MSG_CHANNEL_DATA = 94;
export const SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
export const SSH_MSG_CHANNEL_EOF = 96;
export const SSH_MSG_CHANNEL_CLOSE = 97;
export const SSH_MSG_CHANNEL_REQUEST = 98;
export const SSH_MSG_CHANNEL_SUCCESS = 99;
export const SSH_MSG_CHANNEL_FAILURE = 100;

// Channel open failure reasons
export const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
export const SSH_OPEN_CONNECT_FAILED = 2;
export const SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
export const SSH_OPEN_RESOURCE_SHORTAGE = 4;

// Extended data types
export const SSH_EXTENDED_DATA_STDERR = 1;

// Algorithm names
export const KEX_ALGORITHMS = ["curve25519-sha256"] as const;
export const HOST_KEY_ALGORITHMS = ["ssh-ed25519"] as const;
export const CIPHER_ALGORITHMS = ["aes256-ctr", "aes128-ctr"] as const;
export const MAC_ALGORITHMS = ["hmac-sha2-256", "hmac-sha2-512"] as const;
export const COMPRESSION_ALGORITHMS = ["none"] as const;

// Algorithm properties
export const CIPHER_INFO: Record<
  string,
  { keyLength: number; blockSize: number; ivLength: number }
> = {
  "aes256-ctr": { keyLength: 32, blockSize: 16, ivLength: 16 },
  "aes128-ctr": { keyLength: 16, blockSize: 16, ivLength: 16 },
};

export const MAC_INFO: Record<
  string,
  { keyLength: number; digestLength: number; algorithm: string }
> = {
  "hmac-sha2-256": { keyLength: 32, digestLength: 32, algorithm: "SHA-256" },
  "hmac-sha2-512": { keyLength: 64, digestLength: 64, algorithm: "SHA-512" },
};

// Protocol limits
export const MAX_PACKET_SIZE = 35000;
export const MAX_PAYLOAD_SIZE = 32768;
export const MIN_PADDING = 4;
export const MAX_PADDING = 255;
export const MIN_PACKET_SIZE = 16;

// Default window/channel settings
export const DEFAULT_WINDOW_SIZE = 2 * 1024 * 1024; // 2 MB
export const DEFAULT_MAX_PACKET_SIZE = 32768;

// Software version
export const SOFTWARE_VERSION = "DenoSSH_1.0";
