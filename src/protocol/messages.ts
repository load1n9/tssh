import type * as C from "./constants.ts";

// Transport layer messages (1-21)
export interface DisconnectMessage {
  readonly type: typeof C.SSH_MSG_DISCONNECT;
  reasonCode: number;
  description: string;
  language: string;
}

export interface IgnoreMessage {
  readonly type: typeof C.SSH_MSG_IGNORE;
  data: Uint8Array;
}

export interface UnimplementedMessage {
  readonly type: typeof C.SSH_MSG_UNIMPLEMENTED;
  sequenceNumber: number;
}

export interface DebugMessage {
  readonly type: typeof C.SSH_MSG_DEBUG;
  alwaysDisplay: boolean;
  message: string;
  language: string;
}

export interface ServiceRequestMessage {
  readonly type: typeof C.SSH_MSG_SERVICE_REQUEST;
  serviceName: string;
}

export interface ServiceAcceptMessage {
  readonly type: typeof C.SSH_MSG_SERVICE_ACCEPT;
  serviceName: string;
}

export interface KexInitMessage {
  readonly type: typeof C.SSH_MSG_KEXINIT;
  cookie: Uint8Array;
  kexAlgorithms: string[];
  serverHostKeyAlgorithms: string[];
  encryptionAlgorithmsClientToServer: string[];
  encryptionAlgorithmsServerToClient: string[];
  macAlgorithmsClientToServer: string[];
  macAlgorithmsServerToClient: string[];
  compressionAlgorithmsClientToServer: string[];
  compressionAlgorithmsServerToClient: string[];
  languagesClientToServer: string[];
  languagesServerToClient: string[];
  firstKexPacketFollows: boolean;
  reserved: number;
}

export interface NewKeysMessage {
  readonly type: typeof C.SSH_MSG_NEWKEYS;
}

// Key exchange messages (30-31)
export interface KexEcdhInitMessage {
  readonly type: typeof C.SSH_MSG_KEX_ECDH_INIT;
  clientEphemeralPublicKey: Uint8Array;
}

export interface KexEcdhReplyMessage {
  readonly type: typeof C.SSH_MSG_KEX_ECDH_REPLY;
  hostKey: Uint8Array;
  serverEphemeralPublicKey: Uint8Array;
  signature: Uint8Array;
}

// Authentication messages (50-60)
export interface UserAuthRequestMessage {
  readonly type: typeof C.SSH_MSG_USERAUTH_REQUEST;
  username: string;
  serviceName: string;
  methodName: string;
  methodData: Uint8Array;
}

export interface UserAuthFailureMessage {
  readonly type: typeof C.SSH_MSG_USERAUTH_FAILURE;
  authentications: string[];
  partialSuccess: boolean;
}

export interface UserAuthSuccessMessage {
  readonly type: typeof C.SSH_MSG_USERAUTH_SUCCESS;
}

export interface UserAuthBannerMessage {
  readonly type: typeof C.SSH_MSG_USERAUTH_BANNER;
  message: string;
  language: string;
}

export interface UserAuthPkOkMessage {
  readonly type: typeof C.SSH_MSG_USERAUTH_PK_OK;
  algorithmName: string;
  publicKeyBlob: Uint8Array;
}

// Connection messages (80-100)
export interface GlobalRequestMessage {
  readonly type: typeof C.SSH_MSG_GLOBAL_REQUEST;
  requestName: string;
  wantReply: boolean;
  data: Uint8Array;
}

export interface RequestSuccessMessage {
  readonly type: typeof C.SSH_MSG_REQUEST_SUCCESS;
  data: Uint8Array;
}

export interface RequestFailureMessage {
  readonly type: typeof C.SSH_MSG_REQUEST_FAILURE;
}

export interface ChannelOpenMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_OPEN;
  channelType: string;
  senderChannel: number;
  initialWindowSize: number;
  maximumPacketSize: number;
  extraData: Uint8Array;
}

export interface ChannelOpenConfirmMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
  recipientChannel: number;
  senderChannel: number;
  initialWindowSize: number;
  maximumPacketSize: number;
  extraData: Uint8Array;
}

export interface ChannelOpenFailureMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_OPEN_FAILURE;
  recipientChannel: number;
  reasonCode: number;
  description: string;
  language: string;
}

export interface ChannelWindowAdjustMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_WINDOW_ADJUST;
  recipientChannel: number;
  bytesToAdd: number;
}

export interface ChannelDataMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_DATA;
  recipientChannel: number;
  data: Uint8Array;
}

export interface ChannelExtendedDataMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_EXTENDED_DATA;
  recipientChannel: number;
  dataTypeCode: number;
  data: Uint8Array;
}

export interface ChannelEofMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_EOF;
  recipientChannel: number;
}

export interface ChannelCloseMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_CLOSE;
  recipientChannel: number;
}

export interface ChannelRequestMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_REQUEST;
  recipientChannel: number;
  requestType: string;
  wantReply: boolean;
  requestData: Uint8Array;
}

export interface ChannelSuccessMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_SUCCESS;
  recipientChannel: number;
}

export interface ChannelFailureMessage {
  readonly type: typeof C.SSH_MSG_CHANNEL_FAILURE;
  recipientChannel: number;
}

// Discriminated union of all SSH messages
export type SSHMessage =
  | DisconnectMessage
  | IgnoreMessage
  | UnimplementedMessage
  | DebugMessage
  | ServiceRequestMessage
  | ServiceAcceptMessage
  | KexInitMessage
  | NewKeysMessage
  | KexEcdhInitMessage
  | KexEcdhReplyMessage
  | UserAuthRequestMessage
  | UserAuthFailureMessage
  | UserAuthSuccessMessage
  | UserAuthBannerMessage
  | UserAuthPkOkMessage
  | GlobalRequestMessage
  | RequestSuccessMessage
  | RequestFailureMessage
  | ChannelOpenMessage
  | ChannelOpenConfirmMessage
  | ChannelOpenFailureMessage
  | ChannelWindowAdjustMessage
  | ChannelDataMessage
  | ChannelExtendedDataMessage
  | ChannelEofMessage
  | ChannelCloseMessage
  | ChannelRequestMessage
  | ChannelSuccessMessage
  | ChannelFailureMessage;
