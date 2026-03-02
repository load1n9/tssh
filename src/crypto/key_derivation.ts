import { SSHBufferWriter } from "../protocol/buffer_writer.ts";
import { CIPHER_INFO, MAC_INFO } from "../protocol/constants.ts";
import { sha256 } from "./hash.ts";

export interface NegotiatedAlgorithms {
  kex: string;
  hostKey: string;
  cipherC2S: string;
  cipherS2C: string;
  macC2S: string;
  macS2C: string;
  compressionC2S: string;
  compressionS2C: string;
}

export interface DerivedKeys {
  initialIVClientToServer: Uint8Array;
  initialIVServerToClient: Uint8Array;
  encryptionKeyClientToServer: Uint8Array;
  encryptionKeyServerToClient: Uint8Array;
  integrityKeyClientToServer: Uint8Array;
  integrityKeyServerToClient: Uint8Array;
}

function encodeMpint(v: bigint): Uint8Array {
  const w = new SSHBufferWriter(64);
  w.writeMpint(v);
  return w.toBytes();
}

async function deriveKey(
  sharedSecretMpint: Uint8Array,
  exchangeHash: Uint8Array,
  letter: number,
  sessionId: Uint8Array,
  neededLength: number,
): Promise<Uint8Array> {
  // K1 = HASH(K || H || letter || session_id)
  const input = new Uint8Array(
    sharedSecretMpint.length + exchangeHash.length + 1 + sessionId.length,
  );
  let offset = 0;
  input.set(sharedSecretMpint, offset);
  offset += sharedSecretMpint.length;
  input.set(exchangeHash, offset);
  offset += exchangeHash.length;
  input[offset++] = letter;
  input.set(sessionId, offset);

  let key = await sha256(input);

  // If we need more bytes, extend: Kn = HASH(K || H || K1 || ... || Kn-1)
  while (key.length < neededLength) {
    const extInput = new Uint8Array(
      sharedSecretMpint.length + exchangeHash.length + key.length,
    );
    let o = 0;
    extInput.set(sharedSecretMpint, o);
    o += sharedSecretMpint.length;
    extInput.set(exchangeHash, o);
    o += exchangeHash.length;
    extInput.set(key, o);
    const extra = await sha256(extInput);
    const combined = new Uint8Array(key.length + extra.length);
    combined.set(key);
    combined.set(extra, key.length);
    key = combined;
  }

  return key.slice(0, neededLength);
}

/** Convert a 32-byte raw X25519 shared secret to an SSH mpint bigint */
export function sharedSecretToMpint(rawSecret: Uint8Array): bigint {
  // Interpret as unsigned big-endian integer (network byte order per RFC 8731)
  let val = 0n;
  for (const b of rawSecret) {
    val = (val << 8n) | BigInt(b);
  }
  return val;
}

export async function deriveKeys(
  sharedSecret: bigint,
  exchangeHash: Uint8Array,
  sessionId: Uint8Array,
  algorithms: NegotiatedAlgorithms,
): Promise<DerivedKeys> {
  const kMpint = encodeMpint(sharedSecret);

  const c2sCipher = CIPHER_INFO[algorithms.cipherC2S];
  const s2cCipher = CIPHER_INFO[algorithms.cipherS2C];
  const c2sMac = MAC_INFO[algorithms.macC2S];
  const s2cMac = MAC_INFO[algorithms.macS2C];

  const [ivC2S, ivS2C, encC2S, encS2C, intC2S, intS2C] = await Promise.all([
    deriveKey(kMpint, exchangeHash, 0x41, sessionId, c2sCipher.ivLength), // "A"
    deriveKey(kMpint, exchangeHash, 0x42, sessionId, s2cCipher.ivLength), // "B"
    deriveKey(kMpint, exchangeHash, 0x43, sessionId, c2sCipher.keyLength), // "C"
    deriveKey(kMpint, exchangeHash, 0x44, sessionId, s2cCipher.keyLength), // "D"
    deriveKey(kMpint, exchangeHash, 0x45, sessionId, c2sMac.keyLength), // "E"
    deriveKey(kMpint, exchangeHash, 0x46, sessionId, s2cMac.keyLength), // "F"
  ]);

  return {
    initialIVClientToServer: ivC2S,
    initialIVServerToClient: ivS2C,
    encryptionKeyClientToServer: encC2S,
    encryptionKeyServerToClient: encS2C,
    integrityKeyClientToServer: intC2S,
    integrityKeyServerToClient: intS2C,
  };
}
