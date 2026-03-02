import { signEd25519 } from "../crypto/ed25519.ts";
import type { Ed25519KeyPair } from "../crypto/ed25519.ts";
import { encodeHostKey, encodeSignature } from "../crypto/host_key.ts";
import { SSHBufferReader } from "../protocol/buffer_reader.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";
import * as C from "../protocol/constants.ts";

/** Build method-specific data for public key auth QUERY */
export function buildPublicKeyQueryData(keyPair: Ed25519KeyPair): Uint8Array {
  const w = new SSHBufferWriter(128);
  w.writeBoolean(false);
  w.writeStringFromUTF8("ssh-ed25519");
  w.writeString(encodeHostKey(keyPair.publicKeyBytes));
  return w.toBytes();
}

/** Build the signature data that the client must sign for publickey auth */
export function buildPublicKeySignatureData(
  sessionId: Uint8Array,
  username: string,
  serviceName: string,
  keyPair: Ed25519KeyPair,
): Uint8Array {
  const w = new SSHBufferWriter(512);
  w.writeString(sessionId);
  w.writeByte(C.SSH_MSG_USERAUTH_REQUEST);
  w.writeStringFromUTF8(username);
  w.writeStringFromUTF8(serviceName);
  w.writeStringFromUTF8("publickey");
  w.writeBoolean(true);
  w.writeStringFromUTF8("ssh-ed25519");
  w.writeString(encodeHostKey(keyPair.publicKeyBytes));
  return w.toBytes();
}

/** Build method-specific data for public key auth with signature */
export async function buildPublicKeyAuthData(
  sessionId: Uint8Array,
  username: string,
  serviceName: string,
  keyPair: Ed25519KeyPair,
): Promise<Uint8Array> {
  const sigData = buildPublicKeySignatureData(
    sessionId,
    username,
    serviceName,
    keyPair,
  );
  const sigBytes = await signEd25519(keyPair.privateKey, sigData);
  const sigBlob = encodeSignature(sigBytes);

  const w = new SSHBufferWriter(256);
  w.writeBoolean(true);
  w.writeStringFromUTF8("ssh-ed25519");
  w.writeString(encodeHostKey(keyPair.publicKeyBytes));
  w.writeString(sigBlob);
  return w.toBytes();
}

/** Parse method-specific data for publickey auth on server side */
export function parsePublicKeyAuthData(data: Uint8Array): {
  hasSignature: boolean;
  algorithm: string;
  publicKeyBlob: Uint8Array;
  signature?: Uint8Array;
} {
  const r = new SSHBufferReader(data);
  const hasSignature = r.readBoolean();
  const algorithm = r.readStringAsUTF8();
  const publicKeyBlob = r.readString();
  const signature = hasSignature && r.remaining() > 0
    ? r.readString()
    : undefined;
  return { hasSignature, algorithm, publicKeyBlob, signature };
}
