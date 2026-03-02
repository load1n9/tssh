import type { AuthProvider } from "../auth/auth_types.ts";
import type { Ed25519KeyPair } from "../crypto/ed25519.ts";
import { SSHError } from "../utils/errors.ts";
import { TypedEventEmitter } from "../utils/event_emitter.ts";
import { Logger } from "../utils/logger.ts";
import { ServerConnection } from "./server_connection.ts";

export interface SSHServerConfig {
  hostname?: string;
  port?: number;
  hostKey: Ed25519KeyPair;
  banner?: string;
  authProvider: AuthProvider;
  softwareVersion?: string;
}

export interface ServerEvents {
  connection: ServerConnection;
  error: SSHError;
  listening: Deno.Addr;
}

export class SSHServer extends TypedEventEmitter<ServerEvents> {
  #config: SSHServerConfig;
  #listener: Deno.TcpListener | null = null;
  #connections = new Set<ServerConnection>();
  #logger = new Logger("ssh:server", "warn");
  #closed = false;

  constructor(config: SSHServerConfig) {
    super();
    this.#config = config;
  }

  // deno-lint-ignore require-await
  async listen(): Promise<Deno.Addr> {
    this.#listener = Deno.listen({
      hostname: this.#config.hostname ?? "0.0.0.0",
      port: this.#config.port ?? 22,
      transport: "tcp",
    });

    const addr = this.#listener.addr;
    this.emit("listening", addr);
    this.#logger.info(
      `SSH server listening on ${(addr as Deno.NetAddr).hostname}:${
        (addr as Deno.NetAddr).port
      }`,
    );

    this.#acceptLoop();
    return addr;
  }

  async #acceptLoop(): Promise<void> {
    if (!this.#listener) return;
    try {
      for await (const conn of this.#listener) {
        if (this.#closed) break;
        this.#handleConnection(conn);
      }
    } catch (err) {
      if (!this.#closed) {
        const sshErr = err instanceof SSHError
          ? err
          : new SSHError(String(err));
        this.emit("error", sshErr);
      }
    }
  }

  #handleConnection(tcpConn: Deno.TcpConn): void {
    const serverConn = new ServerConnection(
      tcpConn,
      this.#config.hostKey,
      this.#config.authProvider,
      {
        softwareVersion: this.#config.softwareVersion,
        banner: this.#config.banner,
      },
    );

    this.#connections.add(serverConn);
    serverConn.on("close", () => {
      this.#connections.delete(serverConn);
    });

    this.emit("connection", serverConn);

    serverConn.start().catch((err) => {
      this.#logger.error("Connection error", err);
      this.#connections.delete(serverConn);
    });
  }

  close(): void {
    this.#closed = true;
    if (this.#listener) {
      this.#listener.close();
      this.#listener = null;
    }
    for (const conn of this.#connections) {
      conn.disconnect().catch(() => {});
    }
    this.#connections.clear();
  }
}
