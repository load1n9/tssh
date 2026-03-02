import * as C from "../protocol/constants.ts";
import type { SSHMessage } from "../protocol/messages.ts";
import {
  DisconnectReason,
  SSHError,
  // SSHDisconnectError,
  SSHProtocolError,
} from "../utils/errors.ts";
import { TypedEventEmitter } from "../utils/event_emitter.ts";
import { Logger } from "../utils/logger.ts";
// import type { serializeMessage } from "../protocol/message_serializer.ts";
import { createAESCTRCipher } from "../crypto/aes_ctr.ts";
import type { Ed25519KeyPair } from "../crypto/ed25519.ts";
import { createHMAC } from "../crypto/hmac.ts";
import type {
  DerivedKeys,
  NegotiatedAlgorithms,
} from "../crypto/key_derivation.ts";
import { CIPHER_INFO, SOFTWARE_VERSION } from "../protocol/constants.ts";
import { utf8Encode } from "../utils/encoding.ts";
import { type KexResult, performClientKex, performServerKex } from "./kex.ts";
import { PacketCodec } from "./packet_codec.ts";
import { PacketIO } from "./packet_io.ts";
import { type RekeyConfig, RekeyPolicy } from "./rekey.ts";
import { receiveVersion } from "./version_exchange.ts";

export interface TransportEvents {
  message: SSHMessage;
  close: { reason?: DisconnectReason; description?: string };
  error: SSHError;
}

export interface TransportConfig {
  softwareVersion?: string;
  hostKeyPair?: Ed25519KeyPair;
  rekeyPolicy?: RekeyConfig;
  hostKeyVerifier?: (hostKey: Uint8Array, hostname: string) => Promise<boolean>;
  hostname?: string;
}

export class TransportHandler extends TypedEventEmitter<TransportEvents> {
  #codec: PacketCodec;
  #io: PacketIO;
  #role: "client" | "server";
  #config: TransportConfig;
  #logger: Logger;
  #rekeyPolicy: RekeyPolicy;

  #localVersion = "";
  #remoteVersion = "";
  #sessionId: Uint8Array | undefined;
  #algorithms: NegotiatedAlgorithms | undefined;
  #closed = false;
  #readLoopRunning = false;
  #rekeyInProgress = false;

  constructor(
    readable: ReadableStream<Uint8Array>,
    writable: WritableStream<Uint8Array>,
    role: "client" | "server",
    config: TransportConfig = {},
  ) {
    super();
    this.#role = role;
    this.#config = config;
    this.#logger = new Logger(`ssh:transport:${role}`, "warn");
    this.#io = new PacketIO(readable, writable);
    this.#codec = new PacketCodec(this.#io);
    this.#rekeyPolicy = new RekeyPolicy(config.rekeyPolicy);
  }

  get closed(): boolean {
    return this.#closed;
  }
  get negotiatedAlgorithms(): NegotiatedAlgorithms | undefined {
    return this.#algorithms;
  }
  getSessionId(): Uint8Array | undefined {
    return this.#sessionId;
  }

  async start(): Promise<void> {
    const swVersion = this.#config.softwareVersion ?? SOFTWARE_VERSION;

    if (this.#role === "client") {
      // Client sends version first, then receives
      const _writer = this.#io["writer"]; // Access the underlying writer
      this.#localVersion = `SSH-2.0-${swVersion}`;
      await this.#io.writeRaw(utf8Encode(`${this.#localVersion}\r\n`));

      const { versionString, consumed: _consumed } = await receiveVersion(
        this.#io[
          "reader"
        ] as unknown as ReadableStreamDefaultReader<Uint8Array>,
      );
      this.#remoteVersion = versionString;
      // Note: any bytes after the version line were consumed by receiveVersion
      // and are lost from the reader. The version exchange uses the same reader
      // as packet_io, so no unread is needed since receiveVersion fully consumes.
    } else {
      // Server receives version first, then sends
      const { versionString } = await receiveVersion(
        this.#io[
          "reader"
        ] as unknown as ReadableStreamDefaultReader<Uint8Array>,
      );
      this.#remoteVersion = versionString;

      this.#localVersion = `SSH-2.0-${swVersion}`;
      await this.#io.writeRaw(utf8Encode(`${this.#localVersion}\r\n`));
    }

    this.#logger.debug(`Local version: ${this.#localVersion}`);
    this.#logger.debug(`Remote version: ${this.#remoteVersion}`);

    // Perform initial key exchange
    await this.#performKex();

    // Start the message read loop
    this.#startReadLoop();
  }

  async #performKex(): Promise<void> {
    this.#rekeyInProgress = true;
    try {
      let result: KexResult;

      if (this.#role === "client") {
        result = await performClientKex(
          this.#codec,
          this.#localVersion,
          this.#remoteVersion,
          this.#sessionId,
          this.#config.hostKeyVerifier,
          this.#config.hostname,
        );
      } else {
        if (!this.#config.hostKeyPair) {
          throw new SSHProtocolError("Server must have a host key pair");
        }
        result = await performServerKex(
          this.#codec,
          this.#remoteVersion,
          this.#localVersion,
          this.#config.hostKeyPair,
          this.#sessionId,
        );
      }

      this.#algorithms = result.algorithms;
      this.#sessionId = result.sessionId;

      // Activate new keys
      await this.activateKeys(result.keys, result.algorithms);
      this.#rekeyPolicy.reset();
    } finally {
      this.#rekeyInProgress = false;
    }
  }

  private async activateKeys(
    keys: DerivedKeys,
    algorithms: NegotiatedAlgorithms,
  ): Promise<void> {
    const c2sCipherInfo = CIPHER_INFO[algorithms.cipherC2S];
    const s2cCipherInfo = CIPHER_INFO[algorithms.cipherS2C];

    if (this.#role === "client") {
      // Client encrypts with C2S keys, decrypts with S2C keys
      const encCipher = await createAESCTRCipher(
        keys.encryptionKeyClientToServer,
        keys.initialIVClientToServer,
      );
      const encHmac = await createHMAC(
        algorithms.macC2S as "hmac-sha2-256" | "hmac-sha2-512",
        keys.integrityKeyClientToServer,
      );
      this.#codec.setEncryptionKeys(
        encCipher,
        encHmac,
        c2sCipherInfo.blockSize,
      );

      const decCipher = await createAESCTRCipher(
        keys.encryptionKeyServerToClient,
        keys.initialIVServerToClient,
      );
      const decHmac = await createHMAC(
        algorithms.macS2C as "hmac-sha2-256" | "hmac-sha2-512",
        keys.integrityKeyServerToClient,
      );
      this.#codec.setDecryptionKeys(
        decCipher,
        decHmac,
        s2cCipherInfo.blockSize,
      );
    } else {
      // Server encrypts with S2C keys, decrypts with C2S keys
      const encCipher = await createAESCTRCipher(
        keys.encryptionKeyServerToClient,
        keys.initialIVServerToClient,
      );
      const encHmac = await createHMAC(
        algorithms.macS2C as "hmac-sha2-256" | "hmac-sha2-512",
        keys.integrityKeyServerToClient,
      );
      this.#codec.setEncryptionKeys(
        encCipher,
        encHmac,
        s2cCipherInfo.blockSize,
      );

      const decCipher = await createAESCTRCipher(
        keys.encryptionKeyClientToServer,
        keys.initialIVClientToServer,
      );
      const decHmac = await createHMAC(
        algorithms.macC2S as "hmac-sha2-256" | "hmac-sha2-512",
        keys.integrityKeyClientToServer,
      );
      this.#codec.setDecryptionKeys(
        decCipher,
        decHmac,
        c2sCipherInfo.blockSize,
      );
    }
  }

  #startReadLoop(): void {
    if (this.#readLoopRunning) return;
    this.#readLoopRunning = true;

    (async () => {
      try {
        while (!this.#closed) {
          const msg = await this.#codec.readMessage();
          this.#handleMessage(msg);
        }
      } catch (err) {
        if (!this.#closed) {
          const sshErr = err instanceof SSHError ? err : new SSHProtocolError(
            err instanceof Error ? err.message : String(err),
          );
          this.emit("error", sshErr);
          this.#closed = true;
          this.emit("close", { description: sshErr.message });
        }
      } finally {
        this.#readLoopRunning = false;
      }
    })();
  }

  #handleMessage(msg: SSHMessage): void {
    switch (msg.type) {
      case C.SSH_MSG_DISCONNECT:
        this.#closed = true;
        this.emit("close", {
          reason: msg.reasonCode as DisconnectReason,
          description: msg.description,
        });
        break;

      case C.SSH_MSG_IGNORE:
        // Intentionally ignored
        break;

      case C.SSH_MSG_UNIMPLEMENTED:
        this.#logger.warn(
          `Remote sent UNIMPLEMENTED for seq ${msg.sequenceNumber}`,
        );
        break;

      case C.SSH_MSG_DEBUG:
        this.#logger.debug(`Remote debug: ${msg.message}`);
        break;

      case C.SSH_MSG_KEXINIT:
        // Re-keying initiated by remote side
        // TODO: Handle mid-connection rekey
        break;

      default:
        // Pass all other messages to upper layers
        this.emit("message", msg);
        break;
    }
  }

  async sendMessage(msg: SSHMessage): Promise<void> {
    if (this.#closed) throw new SSHError("Transport is closed");
    await this.#codec.writeMessage(msg);
  }

  async requestService(serviceName: string): Promise<void> {
    await this.sendMessage({
      type: C.SSH_MSG_SERVICE_REQUEST,
      serviceName,
    });

    // Wait for SERVICE_ACCEPT
    return new Promise((resolve, reject) => {
      const handler = (msg: SSHMessage) => {
        if (msg.type === C.SSH_MSG_SERVICE_ACCEPT) {
          if (msg.serviceName === serviceName) {
            this.off("message", handler);
            resolve();
          }
        }
      };
      this.on("message", handler);

      // Timeout after 30 seconds
      setTimeout(() => {
        this.off("message", handler);
        reject(
          new SSHProtocolError(`Service request timeout for ${serviceName}`),
        );
      }, 30000);
    });
  }

  // deno-lint-ignore require-await
  async acceptService(expectedName: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const handler = (msg: SSHMessage) => {
        if (msg.type === C.SSH_MSG_SERVICE_REQUEST) {
          this.off("message", handler);
          if (msg.serviceName === expectedName) {
            this.sendMessage({
              type: C.SSH_MSG_SERVICE_ACCEPT,
              serviceName: msg.serviceName,
            }).then(() => resolve(msg.serviceName));
          } else {
            reject(
              new SSHProtocolError(`Unexpected service: ${msg.serviceName}`),
            );
          }
        }
      };
      this.on("message", handler);

      setTimeout(() => {
        this.off("message", handler);
        reject(new SSHProtocolError("Service request timeout"));
      }, 30000);
    });
  }

  async disconnect(
    reason: DisconnectReason = DisconnectReason.BY_APPLICATION,
    description = "",
  ): Promise<void> {
    if (this.#closed) return;
    try {
      await this.sendMessage({
        type: C.SSH_MSG_DISCONNECT,
        reasonCode: reason,
        description,
        language: "",
      });
    } catch (_) {
      // May fail if connection already broken
    }
    this.#closed = true;
    this.#codec.close();
    this.emit("close", { reason, description });
  }
}
