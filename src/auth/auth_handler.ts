import * as C from "../protocol/constants.ts";
import type { SSHMessage } from "../protocol/messages.ts";
import type { TransportHandler } from "../transport/transport_handler.ts";
import { SSHAuthError } from "../utils/errors.ts";
import type { AuthCredential } from "./auth_types.ts";
import { buildNoneAuthData } from "./none_auth.ts";
import { buildPasswordAuthData } from "./password_auth.ts";
import {
  buildPublicKeyAuthData,
  buildPublicKeyQueryData,
} from "./publickey_auth.ts";

/**
 * Client-side authentication handler.
 * Tries credentials in order: none -> publickey -> password
 */
export class ClientAuthHandler {
  #transport: TransportHandler;
  #credentials: AuthCredential[];
  constructor(transport: TransportHandler, credentials: AuthCredential[]) {
    this.#transport = transport;
    this.#credentials = credentials;
  }

  async authenticate(username: string, serviceName: string): Promise<void> {
    // First try "none" to discover available methods
    const allowedMethods = await this.#tryNone(username, serviceName);

    if (allowedMethods === null) {
      // "none" succeeded (no auth required)
      return;
    }

    // Try each credential
    for (const cred of this.#credentials) {
      if (cred.method === "publickey" && allowedMethods.includes("publickey")) {
        const success = await this.#tryPublicKey(username, serviceName, cred);
        if (success) return;
      } else if (
        cred.method === "password" &&
        allowedMethods.includes("password")
      ) {
        const success = await this.#tryPassword(username, serviceName, cred);
        if (success) return;
      }
    }

    throw new SSHAuthError(
      "All authentication methods exhausted",
      allowedMethods,
    );
  }

  async #tryNone(
    username: string,
    serviceName: string,
  ): Promise<string[] | null> {
    await this.#transport.sendMessage({
      type: C.SSH_MSG_USERAUTH_REQUEST,
      username,
      serviceName,
      methodName: "none",
      methodData: buildNoneAuthData(),
    });

    const reply = await this.#waitForAuthReply();
    if (reply.type === C.SSH_MSG_USERAUTH_SUCCESS) return null;
    if (reply.type === C.SSH_MSG_USERAUTH_FAILURE) return reply.authentications;
    throw new SSHAuthError(`Unexpected auth response: ${reply.type}`);
  }

  async #tryPassword(
    username: string,
    serviceName: string,
    cred: AuthCredential & { method: "password" },
  ): Promise<boolean> {
    await this.#transport.sendMessage({
      type: C.SSH_MSG_USERAUTH_REQUEST,
      username,
      serviceName,
      methodName: "password",
      methodData: buildPasswordAuthData(cred.password),
    });

    const reply = await this.#waitForAuthReply();
    return reply.type === C.SSH_MSG_USERAUTH_SUCCESS;
  }

  async #tryPublicKey(
    username: string,
    serviceName: string,
    cred: AuthCredential & { method: "publickey" },
  ): Promise<boolean> {
    // Phase 1: Query if this key is acceptable
    await this.#transport.sendMessage({
      type: C.SSH_MSG_USERAUTH_REQUEST,
      username,
      serviceName,
      methodName: "publickey",
      methodData: buildPublicKeyQueryData(cred.keyPair),
    });

    const queryReply = await this.#waitForAuthReply();
    if (queryReply.type === C.SSH_MSG_USERAUTH_FAILURE) return false;
    if (queryReply.type !== C.SSH_MSG_USERAUTH_PK_OK) return false;

    // Phase 2: Send actual signature
    const sessionId = this.#transport.getSessionId();
    if (!sessionId) {
      throw new SSHAuthError("No session ID available for public key auth");
    }

    const authData = await buildPublicKeyAuthData(
      sessionId,
      username,
      serviceName,
      cred.keyPair,
    );

    await this.#transport.sendMessage({
      type: C.SSH_MSG_USERAUTH_REQUEST,
      username,
      serviceName,
      methodName: "publickey",
      methodData: authData,
    });

    const reply = await this.#waitForAuthReply();
    return reply.type === C.SSH_MSG_USERAUTH_SUCCESS;
  }

  #waitForAuthReply(): Promise<SSHMessage> {
    return new Promise((resolve, reject) => {
      const handler = (msg: SSHMessage) => {
        if (
          msg.type === C.SSH_MSG_USERAUTH_SUCCESS ||
          msg.type === C.SSH_MSG_USERAUTH_FAILURE ||
          msg.type === C.SSH_MSG_USERAUTH_PK_OK ||
          msg.type === C.SSH_MSG_USERAUTH_BANNER
        ) {
          // Skip banners, wait for actual reply
          if (msg.type === C.SSH_MSG_USERAUTH_BANNER) return;
          this.#transport.off("message", handler);
          resolve(msg);
        }
      };
      this.#transport.on("message", handler);

      setTimeout(() => {
        this.#transport.off("message", handler);
        reject(new SSHAuthError("Authentication timeout"));
      }, 60000);
    });
  }
}
