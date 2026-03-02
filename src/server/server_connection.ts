import { ServerAuthHandler } from "../auth/auth_provider.ts";
import type { AuthProvider } from "../auth/auth_types.ts";
import type { Channel } from "../connection/channel.ts";
import { ConnectionHandler } from "../connection/connection_handler.ts";
import type { Ed25519KeyPair } from "../crypto/ed25519.ts";
import {
  type TransportConfig,
  TransportHandler,
} from "../transport/transport_handler.ts";
import { DisconnectReason, type SSHError } from "../utils/errors.ts";
import { TypedEventEmitter } from "../utils/event_emitter.ts";
import { Logger } from "../utils/logger.ts";
import { ServerForwardManager } from "./server_forwarding.ts";
import { ServerSession } from "./server_session.ts";

export interface ServerConnectionConfig {
  softwareVersion?: string;
  banner?: string;
}

export interface ServerConnectionEvents {
  session: ServerSession;
  close: void;
  error: SSHError;
}

export class ServerConnection
  extends TypedEventEmitter<ServerConnectionEvents> {
  #transport: TransportHandler | null = null;
  #connection: ConnectionHandler | null = null;
  #forwardManager: ServerForwardManager | null = null;
  #logger = new Logger("ssh:server:conn", "warn");
  #username = "";
  #closed = false;
  #tcpConn: Deno.TcpConn;
  #hostKey: Ed25519KeyPair;
  #authProvider: AuthProvider;
  #config: ServerConnectionConfig;
  constructor(
    tcpConn: Deno.TcpConn,
    hostKey: Ed25519KeyPair,
    authProvider: AuthProvider,
    config: ServerConnectionConfig = {},
  ) {
    super();
    this.#tcpConn = tcpConn;
    this.#hostKey = hostKey;
    this.#authProvider = authProvider;
    this.#config = config;
  }

  get username(): string {
    return this.#username;
  }
  get remoteAddr(): Deno.Addr {
    return this.#tcpConn.remoteAddr;
  }

  async start(): Promise<void> {
    // 1. Create transport
    const transportConfig: TransportConfig = {
      softwareVersion: this.#config.softwareVersion,
      hostKeyPair: this.#hostKey,
    };

    this.#transport = new TransportHandler(
      this.#tcpConn.readable,
      this.#tcpConn.writable,
      "server",
      transportConfig,
    );

    this.#transport.on("close", () => {
      this.#closed = true;
      this.emit("close", undefined as unknown as void);
    });
    this.#transport.on("error", (err) => this.emit("error", err));

    // 2. Version exchange + key exchange
    await this.#transport.start();

    // 3. Accept ssh-userauth service request
    await this.#transport.acceptService("ssh-userauth");

    // 4. Handle authentication
    if (this.#config.banner) {
      await this.#transport.sendMessage({
        type: 53, // SSH_MSG_USERAUTH_BANNER
        message: this.#config.banner,
        language: "",
      });
    }

    const authHandler = new ServerAuthHandler(
      this.#transport,
      this.#authProvider,
    );
    const { username } = await authHandler.handleAuth();
    this.#username = username;

    // 5. Set up connection layer
    this.#connection = new ConnectionHandler(this.#transport);
    this.#forwardManager = new ServerForwardManager(
      this.#connection.channelManager,
      this.#connection.globalRequests,
    );

    // 6. Handle incoming channels
    this.#connection.channelManager.onIncomingChannel((channel: Channel) => {
      this.#handleIncomingChannel(channel);
    });
  }

  #handleIncomingChannel(channel: Channel): void {
    if (channel.channelType === "session") {
      const session = new ServerSession(channel);
      this.emit("session", session);
    } else if (channel.channelType === "direct-tcpip" && this.#forwardManager) {
      this.#forwardManager
        .handleDirectTcpip(channel, channel.extraData)
        .catch(() => {});
    }
  }

  async disconnect(reason?: string): Promise<void> {
    if (this.#closed) return;
    this.#forwardManager?.closeAll();
    if (this.#connection) {
      await this.#connection.closeAll();
    }
    if (this.#transport) {
      await this.#transport.disconnect(
        DisconnectReason.BY_APPLICATION,
        reason ?? "Server disconnecting",
      );
    }
    try {
      this.#tcpConn.close();
    } catch (_) {
      /* ignore */
    }
    this.#closed = true;
  }
}
