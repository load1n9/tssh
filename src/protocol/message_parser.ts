import { SSHProtocolError } from "../utils/errors.ts";
import { SSHBufferReader } from "./buffer_reader.ts";
import * as C from "./constants.ts";
import type { SSHMessage } from "./messages.ts";

export function parseMessage(payload: Uint8Array): SSHMessage {
  const r = new SSHBufferReader(payload);
  const type = r.readByte();

  switch (type) {
    case C.SSH_MSG_DISCONNECT:
      return {
        type: C.SSH_MSG_DISCONNECT,
        reasonCode: r.readUint32(),
        description: r.readStringAsUTF8(),
        language: r.readStringAsUTF8(),
      };

    case C.SSH_MSG_IGNORE:
      return {
        type: C.SSH_MSG_IGNORE,
        data: r.readString(),
      };

    case C.SSH_MSG_UNIMPLEMENTED:
      return {
        type: C.SSH_MSG_UNIMPLEMENTED,
        sequenceNumber: r.readUint32(),
      };

    case C.SSH_MSG_DEBUG:
      return {
        type: C.SSH_MSG_DEBUG,
        alwaysDisplay: r.readBoolean(),
        message: r.readStringAsUTF8(),
        language: r.readStringAsUTF8(),
      };

    case C.SSH_MSG_SERVICE_REQUEST:
      return {
        type: C.SSH_MSG_SERVICE_REQUEST,
        serviceName: r.readStringAsUTF8(),
      };

    case C.SSH_MSG_SERVICE_ACCEPT:
      return {
        type: C.SSH_MSG_SERVICE_ACCEPT,
        serviceName: r.readStringAsUTF8(),
      };

    case C.SSH_MSG_KEXINIT:
      return {
        type: C.SSH_MSG_KEXINIT,
        cookie: r.readBytes(16),
        kexAlgorithms: r.readNameList(),
        serverHostKeyAlgorithms: r.readNameList(),
        encryptionAlgorithmsClientToServer: r.readNameList(),
        encryptionAlgorithmsServerToClient: r.readNameList(),
        macAlgorithmsClientToServer: r.readNameList(),
        macAlgorithmsServerToClient: r.readNameList(),
        compressionAlgorithmsClientToServer: r.readNameList(),
        compressionAlgorithmsServerToClient: r.readNameList(),
        languagesClientToServer: r.readNameList(),
        languagesServerToClient: r.readNameList(),
        firstKexPacketFollows: r.readBoolean(),
        reserved: r.readUint32(),
      };

    case C.SSH_MSG_NEWKEYS:
      return { type: C.SSH_MSG_NEWKEYS };

    case C.SSH_MSG_KEX_ECDH_INIT:
      return {
        type: C.SSH_MSG_KEX_ECDH_INIT,
        clientEphemeralPublicKey: r.readString(),
      };

    case C.SSH_MSG_KEX_ECDH_REPLY:
      return {
        type: C.SSH_MSG_KEX_ECDH_REPLY,
        hostKey: r.readString(),
        serverEphemeralPublicKey: r.readString(),
        signature: r.readString(),
      };

    case C.SSH_MSG_USERAUTH_REQUEST:
      return {
        type: C.SSH_MSG_USERAUTH_REQUEST,
        username: r.readStringAsUTF8(),
        serviceName: r.readStringAsUTF8(),
        methodName: r.readStringAsUTF8(),
        methodData: r.rest(),
      };

    case C.SSH_MSG_USERAUTH_FAILURE:
      return {
        type: C.SSH_MSG_USERAUTH_FAILURE,
        authentications: r.readNameList(),
        partialSuccess: r.readBoolean(),
      };

    case C.SSH_MSG_USERAUTH_SUCCESS:
      return { type: C.SSH_MSG_USERAUTH_SUCCESS };

    case C.SSH_MSG_USERAUTH_BANNER:
      return {
        type: C.SSH_MSG_USERAUTH_BANNER,
        message: r.readStringAsUTF8(),
        language: r.readStringAsUTF8(),
      };

    // Note: SSH_MSG_USERAUTH_PK_OK (60) shares the same number as
    // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ. Context determines which it is.
    // We parse as PK_OK since that's our primary use case.
    case C.SSH_MSG_USERAUTH_PK_OK:
      return {
        type: C.SSH_MSG_USERAUTH_PK_OK,
        algorithmName: r.readStringAsUTF8(),
        publicKeyBlob: r.readString(),
      };

    case C.SSH_MSG_GLOBAL_REQUEST:
      return {
        type: C.SSH_MSG_GLOBAL_REQUEST,
        requestName: r.readStringAsUTF8(),
        wantReply: r.readBoolean(),
        data: r.rest(),
      };

    case C.SSH_MSG_REQUEST_SUCCESS:
      return {
        type: C.SSH_MSG_REQUEST_SUCCESS,
        data: r.rest(),
      };

    case C.SSH_MSG_REQUEST_FAILURE:
      return { type: C.SSH_MSG_REQUEST_FAILURE };

    case C.SSH_MSG_CHANNEL_OPEN:
      return {
        type: C.SSH_MSG_CHANNEL_OPEN,
        channelType: r.readStringAsUTF8(),
        senderChannel: r.readUint32(),
        initialWindowSize: r.readUint32(),
        maximumPacketSize: r.readUint32(),
        extraData: r.rest(),
      };

    case C.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
      return {
        type: C.SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
        recipientChannel: r.readUint32(),
        senderChannel: r.readUint32(),
        initialWindowSize: r.readUint32(),
        maximumPacketSize: r.readUint32(),
        extraData: r.rest(),
      };

    case C.SSH_MSG_CHANNEL_OPEN_FAILURE:
      return {
        type: C.SSH_MSG_CHANNEL_OPEN_FAILURE,
        recipientChannel: r.readUint32(),
        reasonCode: r.readUint32(),
        description: r.readStringAsUTF8(),
        language: r.readStringAsUTF8(),
      };

    case C.SSH_MSG_CHANNEL_WINDOW_ADJUST:
      return {
        type: C.SSH_MSG_CHANNEL_WINDOW_ADJUST,
        recipientChannel: r.readUint32(),
        bytesToAdd: r.readUint32(),
      };

    case C.SSH_MSG_CHANNEL_DATA:
      return {
        type: C.SSH_MSG_CHANNEL_DATA,
        recipientChannel: r.readUint32(),
        data: r.readString(),
      };

    case C.SSH_MSG_CHANNEL_EXTENDED_DATA:
      return {
        type: C.SSH_MSG_CHANNEL_EXTENDED_DATA,
        recipientChannel: r.readUint32(),
        dataTypeCode: r.readUint32(),
        data: r.readString(),
      };

    case C.SSH_MSG_CHANNEL_EOF:
      return {
        type: C.SSH_MSG_CHANNEL_EOF,
        recipientChannel: r.readUint32(),
      };

    case C.SSH_MSG_CHANNEL_CLOSE:
      return {
        type: C.SSH_MSG_CHANNEL_CLOSE,
        recipientChannel: r.readUint32(),
      };

    case C.SSH_MSG_CHANNEL_REQUEST:
      return {
        type: C.SSH_MSG_CHANNEL_REQUEST,
        recipientChannel: r.readUint32(),
        requestType: r.readStringAsUTF8(),
        wantReply: r.readBoolean(),
        requestData: r.rest(),
      };

    case C.SSH_MSG_CHANNEL_SUCCESS:
      return {
        type: C.SSH_MSG_CHANNEL_SUCCESS,
        recipientChannel: r.readUint32(),
      };

    case C.SSH_MSG_CHANNEL_FAILURE:
      return {
        type: C.SSH_MSG_CHANNEL_FAILURE,
        recipientChannel: r.readUint32(),
      };

    default:
      throw new SSHProtocolError(`Unknown message type: ${type}`);
  }
}
