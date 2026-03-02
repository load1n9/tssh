import { SSHBufferWriter } from "./buffer_writer.ts";
import * as C from "./constants.ts";
import type { SSHMessage } from "./messages.ts";

export function serializeMessage(msg: SSHMessage): Uint8Array {
  const w = new SSHBufferWriter(512);

  switch (msg.type) {
    case C.SSH_MSG_DISCONNECT:
      w.writeByte(C.SSH_MSG_DISCONNECT);
      w.writeUint32(msg.reasonCode);
      w.writeStringFromUTF8(msg.description);
      w.writeStringFromUTF8(msg.language);
      break;

    case C.SSH_MSG_IGNORE:
      w.writeByte(C.SSH_MSG_IGNORE);
      w.writeString(msg.data);
      break;

    case C.SSH_MSG_UNIMPLEMENTED:
      w.writeByte(C.SSH_MSG_UNIMPLEMENTED);
      w.writeUint32(msg.sequenceNumber);
      break;

    case C.SSH_MSG_DEBUG:
      w.writeByte(C.SSH_MSG_DEBUG);
      w.writeBoolean(msg.alwaysDisplay);
      w.writeStringFromUTF8(msg.message);
      w.writeStringFromUTF8(msg.language);
      break;

    case C.SSH_MSG_SERVICE_REQUEST:
      w.writeByte(C.SSH_MSG_SERVICE_REQUEST);
      w.writeStringFromUTF8(msg.serviceName);
      break;

    case C.SSH_MSG_SERVICE_ACCEPT:
      w.writeByte(C.SSH_MSG_SERVICE_ACCEPT);
      w.writeStringFromUTF8(msg.serviceName);
      break;

    case C.SSH_MSG_KEXINIT:
      w.writeByte(C.SSH_MSG_KEXINIT);
      w.writeRawBytes(msg.cookie);
      w.writeNameList(msg.kexAlgorithms);
      w.writeNameList(msg.serverHostKeyAlgorithms);
      w.writeNameList(msg.encryptionAlgorithmsClientToServer);
      w.writeNameList(msg.encryptionAlgorithmsServerToClient);
      w.writeNameList(msg.macAlgorithmsClientToServer);
      w.writeNameList(msg.macAlgorithmsServerToClient);
      w.writeNameList(msg.compressionAlgorithmsClientToServer);
      w.writeNameList(msg.compressionAlgorithmsServerToClient);
      w.writeNameList(msg.languagesClientToServer);
      w.writeNameList(msg.languagesServerToClient);
      w.writeBoolean(msg.firstKexPacketFollows);
      w.writeUint32(msg.reserved);
      break;

    case C.SSH_MSG_NEWKEYS:
      w.writeByte(C.SSH_MSG_NEWKEYS);
      break;

    case C.SSH_MSG_KEX_ECDH_INIT:
      w.writeByte(C.SSH_MSG_KEX_ECDH_INIT);
      w.writeString(msg.clientEphemeralPublicKey);
      break;

    case C.SSH_MSG_KEX_ECDH_REPLY:
      w.writeByte(C.SSH_MSG_KEX_ECDH_REPLY);
      w.writeString(msg.hostKey);
      w.writeString(msg.serverEphemeralPublicKey);
      w.writeString(msg.signature);
      break;

    case C.SSH_MSG_USERAUTH_REQUEST:
      w.writeByte(C.SSH_MSG_USERAUTH_REQUEST);
      w.writeStringFromUTF8(msg.username);
      w.writeStringFromUTF8(msg.serviceName);
      w.writeStringFromUTF8(msg.methodName);
      w.writeRawBytes(msg.methodData);
      break;

    case C.SSH_MSG_USERAUTH_FAILURE:
      w.writeByte(C.SSH_MSG_USERAUTH_FAILURE);
      w.writeNameList(msg.authentications);
      w.writeBoolean(msg.partialSuccess);
      break;

    case C.SSH_MSG_USERAUTH_SUCCESS:
      w.writeByte(C.SSH_MSG_USERAUTH_SUCCESS);
      break;

    case C.SSH_MSG_USERAUTH_BANNER:
      w.writeByte(C.SSH_MSG_USERAUTH_BANNER);
      w.writeStringFromUTF8(msg.message);
      w.writeStringFromUTF8(msg.language);
      break;

    case C.SSH_MSG_USERAUTH_PK_OK:
      w.writeByte(C.SSH_MSG_USERAUTH_PK_OK);
      w.writeStringFromUTF8(msg.algorithmName);
      w.writeString(msg.publicKeyBlob);
      break;

    case C.SSH_MSG_GLOBAL_REQUEST:
      w.writeByte(C.SSH_MSG_GLOBAL_REQUEST);
      w.writeStringFromUTF8(msg.requestName);
      w.writeBoolean(msg.wantReply);
      w.writeRawBytes(msg.data);
      break;

    case C.SSH_MSG_REQUEST_SUCCESS:
      w.writeByte(C.SSH_MSG_REQUEST_SUCCESS);
      w.writeRawBytes(msg.data);
      break;

    case C.SSH_MSG_REQUEST_FAILURE:
      w.writeByte(C.SSH_MSG_REQUEST_FAILURE);
      break;

    case C.SSH_MSG_CHANNEL_OPEN:
      w.writeByte(C.SSH_MSG_CHANNEL_OPEN);
      w.writeStringFromUTF8(msg.channelType);
      w.writeUint32(msg.senderChannel);
      w.writeUint32(msg.initialWindowSize);
      w.writeUint32(msg.maximumPacketSize);
      w.writeRawBytes(msg.extraData);
      break;

    case C.SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
      w.writeByte(C.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
      w.writeUint32(msg.recipientChannel);
      w.writeUint32(msg.senderChannel);
      w.writeUint32(msg.initialWindowSize);
      w.writeUint32(msg.maximumPacketSize);
      w.writeRawBytes(msg.extraData);
      break;

    case C.SSH_MSG_CHANNEL_OPEN_FAILURE:
      w.writeByte(C.SSH_MSG_CHANNEL_OPEN_FAILURE);
      w.writeUint32(msg.recipientChannel);
      w.writeUint32(msg.reasonCode);
      w.writeStringFromUTF8(msg.description);
      w.writeStringFromUTF8(msg.language);
      break;

    case C.SSH_MSG_CHANNEL_WINDOW_ADJUST:
      w.writeByte(C.SSH_MSG_CHANNEL_WINDOW_ADJUST);
      w.writeUint32(msg.recipientChannel);
      w.writeUint32(msg.bytesToAdd);
      break;

    case C.SSH_MSG_CHANNEL_DATA:
      w.writeByte(C.SSH_MSG_CHANNEL_DATA);
      w.writeUint32(msg.recipientChannel);
      w.writeString(msg.data);
      break;

    case C.SSH_MSG_CHANNEL_EXTENDED_DATA:
      w.writeByte(C.SSH_MSG_CHANNEL_EXTENDED_DATA);
      w.writeUint32(msg.recipientChannel);
      w.writeUint32(msg.dataTypeCode);
      w.writeString(msg.data);
      break;

    case C.SSH_MSG_CHANNEL_EOF:
      w.writeByte(C.SSH_MSG_CHANNEL_EOF);
      w.writeUint32(msg.recipientChannel);
      break;

    case C.SSH_MSG_CHANNEL_CLOSE:
      w.writeByte(C.SSH_MSG_CHANNEL_CLOSE);
      w.writeUint32(msg.recipientChannel);
      break;

    case C.SSH_MSG_CHANNEL_REQUEST:
      w.writeByte(C.SSH_MSG_CHANNEL_REQUEST);
      w.writeUint32(msg.recipientChannel);
      w.writeStringFromUTF8(msg.requestType);
      w.writeBoolean(msg.wantReply);
      w.writeRawBytes(msg.requestData);
      break;

    case C.SSH_MSG_CHANNEL_SUCCESS:
      w.writeByte(C.SSH_MSG_CHANNEL_SUCCESS);
      w.writeUint32(msg.recipientChannel);
      break;

    case C.SSH_MSG_CHANNEL_FAILURE:
      w.writeByte(C.SSH_MSG_CHANNEL_FAILURE);
      w.writeUint32(msg.recipientChannel);
      break;
  }

  return w.toBytes();
}
