import type { NegotiatedAlgorithms } from "../crypto/key_derivation.ts";
import type { KexInitMessage } from "../protocol/messages.ts";
import { SSHProtocolError } from "../utils/errors.ts";

/** Pick the first algorithm from the client's list that the server also supports */
function negotiate(
  clientList: string[],
  serverList: string[],
  what: string,
): string {
  for (const alg of clientList) {
    if (serverList.includes(alg)) return alg;
  }
  throw new SSHProtocolError(
    `No matching ${what}: client=[${clientList}] server=[${serverList}]`,
  );
}

export function negotiateAlgorithms(
  clientInit: KexInitMessage,
  serverInit: KexInitMessage,
): NegotiatedAlgorithms {
  return {
    kex: negotiate(
      clientInit.kexAlgorithms,
      serverInit.kexAlgorithms,
      "kex algorithm",
    ),
    hostKey: negotiate(
      clientInit.serverHostKeyAlgorithms,
      serverInit.serverHostKeyAlgorithms,
      "host key algorithm",
    ),
    cipherC2S: negotiate(
      clientInit.encryptionAlgorithmsClientToServer,
      serverInit.encryptionAlgorithmsClientToServer,
      "cipher (C2S)",
    ),
    cipherS2C: negotiate(
      clientInit.encryptionAlgorithmsServerToClient,
      serverInit.encryptionAlgorithmsServerToClient,
      "cipher (S2C)",
    ),
    macC2S: negotiate(
      clientInit.macAlgorithmsClientToServer,
      serverInit.macAlgorithmsClientToServer,
      "MAC (C2S)",
    ),
    macS2C: negotiate(
      clientInit.macAlgorithmsServerToClient,
      serverInit.macAlgorithmsServerToClient,
      "MAC (S2C)",
    ),
    compressionC2S: negotiate(
      clientInit.compressionAlgorithmsClientToServer,
      serverInit.compressionAlgorithmsClientToServer,
      "compression (C2S)",
    ),
    compressionS2C: negotiate(
      clientInit.compressionAlgorithmsServerToClient,
      serverInit.compressionAlgorithmsServerToClient,
      "compression (S2C)",
    ),
  };
}
