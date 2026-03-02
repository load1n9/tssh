import { importEd25519PublicKey, verifyEd25519 } from "../crypto/ed25519.ts";
import { decodeHostKey, decodeSignature } from "../crypto/host_key.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";
import * as C from "../protocol/constants.ts";
import type { SSHMessage } from "../protocol/messages.ts";
import type { TransportHandler } from "../transport/transport_handler.ts";
import { SSHAuthError } from "../utils/errors.ts";
import type { AuthProvider } from "./auth_types.ts";
import { parsePasswordAuthData } from "./password_auth.ts";
import { parsePublicKeyAuthData } from "./publickey_auth.ts";

const MAX_AUTH_ATTEMPTS = 20;
const AUTH_TIMEOUT_MS = 60000;

/**
 * Server-side authentication handler.
 * Receives auth requests and validates against AuthProvider.
 */
export class ServerAuthHandler {
  #transport: TransportHandler;
  #provider: AuthProvider;
  constructor(transport: TransportHandler, provider: AuthProvider) {
    this.#transport = transport;
    this.#provider = provider;
  }

  // deno-lint-ignore require-await
  async handleAuth(): Promise<{ username: string; serviceName: string }> {
    let attempts = 0;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.#transport.off("message", handler);
        reject(new SSHAuthError("Authentication timeout"));
      }, AUTH_TIMEOUT_MS);

      const handler = async (msg: SSHMessage) => {
        if (msg.type !== C.SSH_MSG_USERAUTH_REQUEST) return;

        attempts++;
        if (attempts > MAX_AUTH_ATTEMPTS) {
          clearTimeout(timeout);
          this.#transport.off("message", handler);
          reject(new SSHAuthError("Too many authentication attempts"));
          return;
        }

        try {
          const success = await this.#processAuthRequest(msg);
          if (success) {
            clearTimeout(timeout);
            this.#transport.off("message", handler);
            await this.#transport.sendMessage({
              type: C.SSH_MSG_USERAUTH_SUCCESS,
            });
            resolve({ username: msg.username, serviceName: msg.serviceName });
          } else {
            const methods = await this.#provider.getAllowedMethods(
              msg.username,
            );
            await this.#transport.sendMessage({
              type: C.SSH_MSG_USERAUTH_FAILURE,
              authentications: methods,
              partialSuccess: false,
            });
          }
        } catch (err) {
          clearTimeout(timeout);
          this.#transport.off("message", handler);
          reject(err);
        }
      };

      this.#transport.on("message", handler);
    });
  }

  async #processAuthRequest(msg: {
    username: string;
    serviceName: string;
    methodName: string;
    methodData: Uint8Array;
  }): Promise<boolean> {
    switch (msg.methodName) {
      case "none":
        return false;

      case "password": {
        const { password } = parsePasswordAuthData(msg.methodData);
        return this.#provider.authenticatePassword(msg.username, password);
      }

      case "publickey": {
        const { hasSignature, algorithm, publicKeyBlob, signature } =
          parsePublicKeyAuthData(msg.methodData);

        if (!hasSignature) {
          // Query phase: check if this key is accepted
          const accepted = await this.#provider.authenticatePublicKey(
            msg.username,
            publicKeyBlob,
          );
          if (accepted) {
            await this.#transport.sendMessage({
              type: C.SSH_MSG_USERAUTH_PK_OK,
              algorithmName: algorithm,
              publicKeyBlob,
            });
          }
          return false; // Not yet authenticated
        }

        // Verify phase: check key acceptance and signature
        const keyAccepted = await this.#provider.authenticatePublicKey(
          msg.username,
          publicKeyBlob,
        );
        if (!keyAccepted) return false;

        if (!signature) return false;

        // Verify signature
        const sessionId = this.#transport.getSessionId();
        if (!sessionId) return false;

        const { keyBytes } = decodeHostKey(publicKeyBlob);
        const pubKey = await importEd25519PublicKey(keyBytes);

        // Build the data that should have been signed
        const w = new SSHBufferWriter(512);
        w.writeString(sessionId);
        w.writeByte(C.SSH_MSG_USERAUTH_REQUEST);
        w.writeStringFromUTF8(msg.username);
        w.writeStringFromUTF8(msg.serviceName);
        w.writeStringFromUTF8("publickey");
        w.writeBoolean(true);
        w.writeStringFromUTF8(algorithm);
        w.writeString(publicKeyBlob);
        const signedData = w.toBytes();

        const { signatureBytes } = decodeSignature(signature);
        return verifyEd25519(pubKey, signatureBytes, signedData);
      }

      default:
        return false;
    }
  }
}
