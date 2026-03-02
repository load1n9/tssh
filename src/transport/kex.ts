import {
  importEd25519PublicKey,
  signEd25519,
  verifyEd25519,
} from "../crypto/ed25519.ts";
import type { Ed25519KeyPair } from "../crypto/ed25519.ts";
import { sha256 } from "../crypto/hash.ts";
import {
  decodeHostKey,
  decodeSignature,
  encodeHostKey,
  encodeSignature,
} from "../crypto/host_key.ts";
import {
  type DerivedKeys,
  deriveKeys,
  type NegotiatedAlgorithms,
  sharedSecretToMpint,
} from "../crypto/key_derivation.ts";
import { randomBytes } from "../crypto/random.ts";
import {
  deriveX25519SharedSecret,
  generateX25519KeyPair,
} from "../crypto/x25519.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";
import * as C from "../protocol/constants.ts";
import { parseMessage } from "../protocol/message_parser.ts";
import { serializeMessage } from "../protocol/message_serializer.ts";
import type { KexInitMessage } from "../protocol/messages.ts";
import { SSHCryptoError, SSHProtocolError } from "../utils/errors.ts";
import { negotiateAlgorithms } from "./kex_algorithms.ts";
import type { PacketCodec } from "./packet_codec.ts";

export interface KexResult {
  algorithms: NegotiatedAlgorithms;
  keys: DerivedKeys;
  sessionId: Uint8Array;
  exchangeHash: Uint8Array;
}

function buildKexInit(): KexInitMessage {
  return {
    type: C.SSH_MSG_KEXINIT,
    cookie: randomBytes(16),
    kexAlgorithms: [...C.KEX_ALGORITHMS],
    serverHostKeyAlgorithms: [...C.HOST_KEY_ALGORITHMS],
    encryptionAlgorithmsClientToServer: [...C.CIPHER_ALGORITHMS],
    encryptionAlgorithmsServerToClient: [...C.CIPHER_ALGORITHMS],
    macAlgorithmsClientToServer: [...C.MAC_ALGORITHMS],
    macAlgorithmsServerToClient: [...C.MAC_ALGORITHMS],
    compressionAlgorithmsClientToServer: [...C.COMPRESSION_ALGORITHMS],
    compressionAlgorithmsServerToClient: [...C.COMPRESSION_ALGORITHMS],
    languagesClientToServer: [],
    languagesServerToClient: [],
    firstKexPacketFollows: false,
    reserved: 0,
  };
}

/**
 * Compute the exchange hash H for curve25519-sha256:
 *   H = SHA-256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
 * All values are encoded as SSH strings (uint32 length + data).
 */
// deno-lint-ignore require-await
async function computeExchangeHash(
  clientVersion: string,
  serverVersion: string,
  clientKexInitPayload: Uint8Array,
  serverKexInitPayload: Uint8Array,
  hostKeyBlob: Uint8Array,
  clientEphemeralPub: Uint8Array,
  serverEphemeralPub: Uint8Array,
  sharedSecret: bigint,
): Promise<Uint8Array> {
  const w = new SSHBufferWriter(2048);
  w.writeStringFromUTF8(clientVersion);
  w.writeStringFromUTF8(serverVersion);
  w.writeString(clientKexInitPayload);
  w.writeString(serverKexInitPayload);
  w.writeString(hostKeyBlob);
  w.writeString(clientEphemeralPub);
  w.writeString(serverEphemeralPub);
  w.writeMpint(sharedSecret);
  return sha256(w.toBytes());
}

export async function performClientKex(
  codec: PacketCodec,
  clientVersion: string,
  serverVersion: string,
  existingSessionId?: Uint8Array,
  hostKeyVerifier?: (hostKey: Uint8Array, hostname: string) => Promise<boolean>,
  hostname?: string,
): Promise<KexResult> {
  // 1. Send our KEXINIT
  const clientKexInit = buildKexInit();
  const clientKexInitPayload = serializeMessage(clientKexInit);
  await codec.writePayload(clientKexInitPayload);

  // 2. Receive server KEXINIT
  const serverKexInitPayload = await codec.readPayload();
  const serverKexInit = parseMessage(serverKexInitPayload);
  if (serverKexInit.type !== C.SSH_MSG_KEXINIT) {
    throw new SSHProtocolError(`Expected KEXINIT, got ${serverKexInit.type}`);
  }

  // 3. Negotiate algorithms
  const algorithms = negotiateAlgorithms(clientKexInit, serverKexInit);

  // 4. Generate ephemeral X25519 key pair
  const ephemeral = await generateX25519KeyPair();

  // 5. Send KEX_ECDH_INIT
  await codec.writeMessage({
    type: C.SSH_MSG_KEX_ECDH_INIT,
    clientEphemeralPublicKey: ephemeral.publicKeyBytes,
  });

  // 6. Receive KEX_ECDH_REPLY
  const reply = await codec.readMessage();
  if (reply.type !== C.SSH_MSG_KEX_ECDH_REPLY) {
    throw new SSHProtocolError(`Expected KEX_ECDH_REPLY, got ${reply.type}`);
  }

  // 7. Derive shared secret
  const rawSecret = await deriveX25519SharedSecret(
    ephemeral.privateKey,
    reply.serverEphemeralPublicKey,
  );
  const sharedSecret = sharedSecretToMpint(rawSecret);

  // 8. Compute exchange hash
  const exchangeHash = await computeExchangeHash(
    clientVersion,
    serverVersion,
    clientKexInitPayload,
    serverKexInitPayload,
    reply.hostKey,
    ephemeral.publicKeyBytes,
    reply.serverEphemeralPublicKey,
    sharedSecret,
  );

  // 9. Verify host key signature
  const { keyBytes } = decodeHostKey(reply.hostKey);
  const { signatureBytes } = decodeSignature(reply.signature);
  const hostPubKey = await importEd25519PublicKey(keyBytes);
  const sigValid = await verifyEd25519(
    hostPubKey,
    signatureBytes,
    exchangeHash,
  );
  if (!sigValid) {
    throw new SSHCryptoError("Host key signature verification failed");
  }

  // 10. Optional host key verification callback
  if (hostKeyVerifier) {
    const trusted = await hostKeyVerifier(reply.hostKey, hostname ?? "");
    if (!trusted) {
      throw new SSHCryptoError("Host key not trusted");
    }
  }

  // 11. session_id = H on first kex, unchanged on rekey
  const sessionId = existingSessionId ?? exchangeHash;

  // 12. Send NEWKEYS
  await codec.writeMessage({ type: C.SSH_MSG_NEWKEYS });

  // 13. Receive NEWKEYS
  const newkeys = await codec.readMessage();
  if (newkeys.type !== C.SSH_MSG_NEWKEYS) {
    throw new SSHProtocolError(`Expected NEWKEYS, got ${newkeys.type}`);
  }

  // 14. Derive session keys
  const keys = await deriveKeys(
    sharedSecret,
    exchangeHash,
    sessionId,
    algorithms,
  );

  return { algorithms, keys, sessionId, exchangeHash };
}

export async function performServerKex(
  codec: PacketCodec,
  clientVersion: string,
  serverVersion: string,
  hostKeyPair: Ed25519KeyPair,
  existingSessionId?: Uint8Array,
): Promise<KexResult> {
  // 1. Receive client KEXINIT
  const clientKexInitPayload = await codec.readPayload();
  const clientKexInit = parseMessage(clientKexInitPayload);
  if (clientKexInit.type !== C.SSH_MSG_KEXINIT) {
    throw new SSHProtocolError(`Expected KEXINIT, got ${clientKexInit.type}`);
  }

  // 2. Send our KEXINIT
  const serverKexInit = buildKexInit();
  const serverKexInitPayload = serializeMessage(serverKexInit);
  await codec.writePayload(serverKexInitPayload);

  // 3. Negotiate algorithms
  const algorithms = negotiateAlgorithms(clientKexInit, serverKexInit);

  // 4. Receive KEX_ECDH_INIT
  const init = await codec.readMessage();
  if (init.type !== C.SSH_MSG_KEX_ECDH_INIT) {
    throw new SSHProtocolError(`Expected KEX_ECDH_INIT, got ${init.type}`);
  }

  // 5. Generate ephemeral X25519 key pair
  const ephemeral = await generateX25519KeyPair();

  // 6. Derive shared secret
  const rawSecret = await deriveX25519SharedSecret(
    ephemeral.privateKey,
    init.clientEphemeralPublicKey,
  );
  const sharedSecret = sharedSecretToMpint(rawSecret);

  // 7. Encode host key blob
  const hostKeyBlob = encodeHostKey(hostKeyPair.publicKeyBytes);

  // 8. Compute exchange hash
  const exchangeHash = await computeExchangeHash(
    clientVersion,
    serverVersion,
    clientKexInitPayload,
    serverKexInitPayload,
    hostKeyBlob,
    init.clientEphemeralPublicKey,
    ephemeral.publicKeyBytes,
    sharedSecret,
  );

  // 9. Sign exchange hash
  const sigBytes = await signEd25519(hostKeyPair.privateKey, exchangeHash);
  const signatureBlob = encodeSignature(sigBytes);

  // 10. Send KEX_ECDH_REPLY
  await codec.writeMessage({
    type: C.SSH_MSG_KEX_ECDH_REPLY,
    hostKey: hostKeyBlob,
    serverEphemeralPublicKey: ephemeral.publicKeyBytes,
    signature: signatureBlob,
  });

  // 11. session_id = H on first kex
  const sessionId = existingSessionId ?? exchangeHash;

  // 12. Send NEWKEYS
  await codec.writeMessage({ type: C.SSH_MSG_NEWKEYS });

  // 13. Receive NEWKEYS
  const newkeys = await codec.readMessage();
  if (newkeys.type !== C.SSH_MSG_NEWKEYS) {
    throw new SSHProtocolError(`Expected NEWKEYS, got ${newkeys.type}`);
  }

  // 14. Derive session keys
  const keys = await deriveKeys(
    sharedSecret,
    exchangeHash,
    sessionId,
    algorithms,
  );

  return { algorithms, keys, sessionId, exchangeHash };
}
