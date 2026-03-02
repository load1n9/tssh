// deno-lint-ignore-file require-await

import {
  type AuthProvider,
  generateEd25519KeyPair,
  type ServerConnection,
  type ServerSession,
  SSHServer,
} from "../mod.ts";

const encoder = new TextEncoder();

const authProvider: AuthProvider = {
  async authenticatePassword(username: string, password: string) {
    return username === "demo" && password === "secret";
  },
  async authenticatePublicKey() {
    return false;
  },
  async getAllowedMethods() {
    return ["password"];
  },
};

const hostKey = await generateEd25519KeyPair();
const hostname =
  prompt("Hostname to bind SSH server to (default: 127.0.0.1)") || "127.0.0.1";
const portInput = prompt("Port to listen on (default: 2222)") || "2222";
const port = parseInt(portInput, 10);
const server = new SSHServer({
  hostname,
  port,
  hostKey,
  authProvider,
});

server.on("connection", (conn: ServerConnection) => {
  console.log(
    `Client connected: ${(conn.remoteAddr as Deno.NetAddr).hostname}`,
  );

  conn.on("session", (session: ServerSession) => {
    session.on("exec", async ({ command }) => {
      console.log(`exec: ${command}`);
      await session.write(encoder.encode(`echo: ${command}\n`));
      await session.exit(0);
    });

    session.on("shell", async () => {
      console.log("shell opened");
      await session.write(
        encoder.encode("Welcome! Type 'exit' to quit.\r\n> "),
      );

      let line = "";
      session.channel.on("data", async (data: Uint8Array) => {
        for (const byte of data) {
          if (byte === 0x7f || byte === 0x08) {
            if (line.length > 0) {
              line = line.slice(0, -1);
              await session.write(encoder.encode("\b \b"));
            }
          } else if (byte === 0x03) {
            // Ctrl-C
            await session.write(encoder.encode("^C\r\n"));
            await session.exit(130);
            return;
          } else if (byte === 0x0d) {
            // Enter (carriage return)
            await session.write(encoder.encode("\r\n"));
            const cmd = line.trim();
            line = "";

            if (cmd === "exit") {
              await session.write(encoder.encode("Goodbye!\r\n"));
              await session.exit(0);
              return;
            }

            if (cmd.length > 0) {
              await session.write(encoder.encode(`echo: ${cmd}\r\n`));
            }
            await session.write(encoder.encode("> "));
          } else if (byte >= 0x20 && byte < 0x7f) {
            line += String.fromCharCode(byte);
            await session.write(new Uint8Array([byte]));
          }
        }
      });

      session.on("eof", () => {
        session.exit(0);
      });
    });
  });

  conn.on("close", () => {
    console.log("Client disconnected");
  });
});

const addr = await server.listen();
console.log(
  `SSH server listening on ${(addr as Deno.NetAddr).hostname}:${
    (addr as Deno.NetAddr).port
  }`,
);
console.log(
  `Connect with: ssh demo@${hostname} -p ${port}  (password: "secret")`,
);
