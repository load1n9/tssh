import { SSHCryptoError } from "../utils/errors.ts";

export interface X25519KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyBytes: Uint8Array;
}

export async function generateX25519KeyPair(): Promise<X25519KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    "X25519",
    true,
    ["deriveBits"],
  ) as CryptoKeyPair;

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyBytes,
  };
}

export async function deriveX25519SharedSecret(
  privateKey: CryptoKey,
  remotePublicKeyBytes: Uint8Array,
): Promise<Uint8Array> {
  const remotePublicKey = await crypto.subtle.importKey(
    "raw",
    remotePublicKeyBytes as Uint8Array<ArrayBuffer>,
    "X25519",
    false,
    [],
  );

  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: remotePublicKey },
      privateKey,
      256,
    ),
  );

  // RFC 8731: Check for all-zero shared secret
  let allZero = true;
  for (const b of sharedSecret) {
    if (b !== 0) {
      allZero = false;
      break;
    }
  }
  if (allZero) {
    throw new SSHCryptoError("X25519 shared secret is all-zero");
  }

  return sharedSecret;
}
