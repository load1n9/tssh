import { SSHBufferReader } from "../protocol/buffer_reader.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";

/** Encode an Ed25519 public key as an SSH public key blob:
 *  string "ssh-ed25519" | string key(32 bytes) */
export function encodeHostKey(publicKeyBytes: Uint8Array): Uint8Array {
  const w = new SSHBufferWriter(64);
  w.writeStringFromUTF8("ssh-ed25519");
  w.writeString(publicKeyBytes);
  return w.toBytes();
}

/** Decode an SSH public key blob to extract the raw Ed25519 key bytes */
export function decodeHostKey(
  blob: Uint8Array,
): { algorithm: string; keyBytes: Uint8Array } {
  const r = new SSHBufferReader(blob);
  const algorithm = r.readStringAsUTF8();
  const keyBytes = r.readString();
  return { algorithm, keyBytes };
}

/** Encode an Ed25519 signature as an SSH signature blob:
 *  string "ssh-ed25519" | string sig(64 bytes) */
export function encodeSignature(signatureBytes: Uint8Array): Uint8Array {
  const w = new SSHBufferWriter(128);
  w.writeStringFromUTF8("ssh-ed25519");
  w.writeString(signatureBytes);
  return w.toBytes();
}

/** Decode an SSH signature blob to extract the raw signature bytes */
export function decodeSignature(
  blob: Uint8Array,
): { algorithm: string; signatureBytes: Uint8Array } {
  const r = new SSHBufferReader(blob);
  const algorithm = r.readStringAsUTF8();
  const signatureBytes = r.readString();
  return { algorithm, signatureBytes };
}
