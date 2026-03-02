// deno-lint-ignore-file require-await
export interface Ed25519KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyBytes: Uint8Array;
}

export async function generateEd25519KeyPair(): Promise<Ed25519KeyPair> {
  const keyPair = (await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyBytes,
  };
}

export async function signEd25519(
  privateKey: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(sig);
}

export async function verifyEd25519(
  publicKey: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  return crypto.subtle.verify(
    "Ed25519",
    publicKey,
    signature as Uint8Array<ArrayBuffer>,
    data as Uint8Array<ArrayBuffer>,
  );
}

export async function importEd25519PublicKey(
  raw: Uint8Array,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw as Uint8Array<ArrayBuffer>,
    "Ed25519",
    true,
    ["verify"],
  );
}

export async function importEd25519PrivateKey(
  pkcs8: Uint8Array,
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8 as Uint8Array<ArrayBuffer>,
    "Ed25519",
    true,
    ["sign"],
  );
}

export async function exportEd25519PublicKeyRaw(
  key: CryptoKey,
): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

export async function exportEd25519PrivateKeyPkcs8(
  key: CryptoKey,
): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("pkcs8", key));
}
