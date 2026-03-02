export enum DisconnectReason {
  HOST_NOT_ALLOWED_TO_CONNECT = 1,
  PROTOCOL_ERROR = 2,
  KEY_EXCHANGE_FAILED = 3,
  RESERVED = 4,
  MAC_ERROR = 5,
  COMPRESSION_ERROR = 6,
  SERVICE_NOT_AVAILABLE = 7,
  PROTOCOL_VERSION_NOT_SUPPORTED = 8,
  HOST_KEY_NOT_VERIFIABLE = 9,
  CONNECTION_LOST = 10,
  BY_APPLICATION = 11,
  TOO_MANY_CONNECTIONS = 12,
  AUTH_CANCELLED_BY_USER = 13,
  NO_MORE_AUTH_METHODS_AVAILABLE = 14,
  ILLEGAL_USER_NAME = 15,
}

export class SSHError extends Error {
  constructor(message: string, public readonly code?: number) {
    super(message);
    this.name = "SSHError";
  }
}

export class SSHDisconnectError extends SSHError {
  constructor(
    public readonly reason: DisconnectReason,
    description: string,
  ) {
    super(description, reason);
    this.name = "SSHDisconnectError";
  }
}

export class SSHProtocolError extends SSHError {
  constructor(message: string) {
    super(message);
    this.name = "SSHProtocolError";
  }
}

export class SSHAuthError extends SSHError {
  constructor(
    message: string,
    public readonly allowedMethods?: string[],
  ) {
    super(message);
    this.name = "SSHAuthError";
  }
}

export class SSHChannelError extends SSHError {
  constructor(message: string, public readonly channelId?: number) {
    super(message);
    this.name = "SSHChannelError";
  }
}

export class SSHCryptoError extends SSHError {
  constructor(message: string) {
    super(message);
    this.name = "SSHCryptoError";
  }
}

export class SFTPError extends SSHError {
  constructor(message: string, public readonly statusCode: number) {
    super(message, statusCode);
    this.name = "SFTPError";
  }
}
