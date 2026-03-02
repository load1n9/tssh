// deno-lint-ignore-file require-await
import { AgentForwardHandler } from "../agent/agent_forwarding.ts";
import { ClientAuthHandler } from "../auth/auth_handler.ts";
import type { AuthCredential } from "../auth/auth_types.ts";
import { ConnectionHandler } from "../connection/connection_handler.ts";
import {
  type LocalForwardConfig,
  LocalForwardManager,
} from "../connection/forwarding_channel.ts";
import {
  type PtyOptions,
  SessionChannel,
} from "../connection/session_channel.ts";
import type { Ed25519KeyPair } from "../crypto/ed25519.ts";
import { SftpClient } from "../sftp/sftp_client.ts";
import {
  type TransportConfig,
  TransportHandler,
} from "../transport/transport_handler.ts";
import { DisconnectReason, SSHError } from "../utils/errors.ts";
import { TypedEventEmitter } from "../utils/event_emitter.ts";

export interface SSHClientConfig {
  hostname: string;
  port?: number;
  username: string;
  password?: string;
  privateKey?: Ed25519KeyPair;
  hostKeyVerifier?: (hostKey: Uint8Array, hostname: string) => Promise<boolean>;
  softwareVersion?: string;
  agentSocketPath?: string;
}

export interface ExecResult {
  stdout: Uint8Array;
  stderr: Uint8Array;
  exitCode: number;
}

export interface ClientEvents {
  banner: string;
  ready: void;
  close: { reason?: DisconnectReason; description?: string };
  error: SSHError;
}

export class SSHClient extends TypedEventEmitter<ClientEvents> {
  #config: SSHClientConfig;
  #transport: TransportHandler | null = null;
  #connection: ConnectionHandler | null = null;
  #localForwards: LocalForwardManager | null = null;
  #agentHandler: AgentForwardHandler | null = null;
  #tcpConn: Deno.TcpConn | null = null;

  constructor(config: SSHClientConfig) {
    super();
    this.#config = config;
  }

  async connect(): Promise<void> {
    const port = this.#config.port ?? 22;

    // 1. TCP connect
    this.#tcpConn = await Deno.connect({
      hostname: this.#config.hostname,
      port,
      transport: "tcp",
    });

    // 2. Create transport
    const transportConfig: TransportConfig = {
      softwareVersion: this.#config.softwareVersion,
      hostKeyVerifier: this.#config.hostKeyVerifier,
      hostname: this.#config.hostname,
    };

    this.#transport = new TransportHandler(
      this.#tcpConn.readable,
      this.#tcpConn.writable,
      "client",
      transportConfig,
    );

    this.#transport.on("close", (data) => this.emit("close", data));
    this.#transport.on("error", (err) => this.emit("error", err));

    // 3. Version exchange + key exchange
    await this.#transport.start();

    // 4. Request ssh-userauth service
    await this.#transport.requestService("ssh-userauth");

    // 5. Authenticate
    const credentials: AuthCredential[] = [];
    if (this.#config.privateKey) {
      credentials.push({
        method: "publickey",
        username: this.#config.username,
        keyPair: this.#config.privateKey,
      });
    }
    if (this.#config.password) {
      credentials.push({
        method: "password",
        username: this.#config.username,
        password: this.#config.password,
      });
    }

    const authHandler = new ClientAuthHandler(this.#transport, credentials);
    await authHandler.authenticate(this.#config.username, "ssh-connection");

    // 6. Set up connection layer
    this.#connection = new ConnectionHandler(this.#transport);
    this.#localForwards = new LocalForwardManager(
      this.#connection.channelManager,
    );

    if (this.#config.agentSocketPath) {
      this.#agentHandler = new AgentForwardHandler(
        this.#config.agentSocketPath,
      );
    }

    this.emit("ready", undefined as unknown as void);
  }

  async exec(command: string): Promise<ExecResult> {
    if (!this.#connection) throw new SSHError("Not connected");

    const channel = await this.#connection.channelManager.openChannel(
      "session",
    );
    const session = new SessionChannel(channel);

    const success = await session.requestExec(command);
    if (!success) throw new SSHError("Exec request rejected");

    const [stdout, stderr, exitCode] = await Promise.all([
      session.collectStdout(),
      session.collectStderr(),
      session.exitStatus,
    ]);

    return { stdout, stderr, exitCode };
  }

  async shell(opts?: PtyOptions): Promise<SessionChannel> {
    if (!this.#connection) throw new SSHError("Not connected");

    const channel = await this.#connection.channelManager.openChannel(
      "session",
    );
    const session = new SessionChannel(channel);

    if (opts) {
      await session.requestPty(opts);
    }

    await session.requestShell();
    return session;
  }

  async sftp(): Promise<SftpClient> {
    if (!this.#connection) throw new SSHError("Not connected");

    const channel = await this.#connection.channelManager.openChannel(
      "session",
    );
    const session = new SessionChannel(channel);

    const success = await session.requestSubsystem("sftp");
    if (!success) throw new SSHError("SFTP subsystem request rejected");

    const client = new SftpClient(channel);
    await client.initialize();
    return client;
  }

  async forwardLocalPort(config: LocalForwardConfig): Promise<void> {
    if (!this.#localForwards) throw new SSHError("Not connected");
    await this.#localForwards.addForward(config);
  }

  async forwardRemotePort(
    remoteAddress: string,
    remotePort: number,
    _localAddress: string,
    _localPort: number,
  ): Promise<number | null> {
    if (!this.#connection) throw new SSHError("Not connected");
    return this.#connection.globalRequests.requestTcpipForward(
      remoteAddress,
      remotePort,
    );
  }

  async rekey(): Promise<void> {
    // TODO: Implement mid-connection rekeying
    throw new SSHError("Rekey not yet implemented");
  }

  async disconnect(reason?: string): Promise<void> {
    this.#localForwards?.closeAll();
    if (this.#transport) {
      await this.#transport.disconnect(
        DisconnectReason.BY_APPLICATION,
        reason ?? "Client disconnecting",
      );
    }
    try {
      this.#tcpConn?.close();
    } catch (_) {
      /* ignore */
    }
  }

  get isConnected(): boolean {
    return this.#transport !== null && !this.#transport.closed;
  }
}
