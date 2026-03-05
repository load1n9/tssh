/**
 * Web-Based Terminal — SSH-to-WebSocket Bridge
 *
 * A Deno server that exposes a WebSocket endpoint, connects to a remote SSH
 * server via tssh, and pipes an interactive shell session to a browser-based
 * xterm.js terminal.
 *
 * Usage:
 *   deno run --allow-net --allow-read main.ts
 *
 * Then open http://localhost:8080 in your browser.
 *
 * Environment variables (all optional — falls back to defaults):
 *   SSH_HOST      — remote SSH host      (default: 127.0.0.1)
 *   SSH_PORT      — remote SSH port      (default: 22)
 *   SSH_USER      — SSH username          (default: demo)
 *   SSH_PASSWORD  — SSH password          (default: secret)
 *   LISTEN_PORT   — HTTP/WS listen port  (default: 8080)
 */

import { SSHClient, type SessionChannel } from "../../mod.ts";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SSH_HOST = Deno.env.get("SSH_HOST") ?? "127.0.0.1";
const SSH_PORT = Number(Deno.env.get("SSH_PORT") ?? "22");
const SSH_USER = Deno.env.get("SSH_USER") ?? "demo";
const SSH_PASSWORD = Deno.env.get("SSH_PASSWORD") ?? "secret";
const LISTEN_PORT = Number(Deno.env.get("LISTEN_PORT") ?? "8080");

// ---------------------------------------------------------------------------
// Serve static HTML for the xterm.js frontend
// ---------------------------------------------------------------------------

const HTML = await Deno.readTextFile(
  new URL("./index.html", import.meta.url),
);

// ---------------------------------------------------------------------------
// Handle a single WebSocket connection
// ---------------------------------------------------------------------------

async function handleWebSocket(ws: WebSocket): Promise<void> {
  console.log("[ws] client connected");

  const client = new SSHClient({
    hostname: SSH_HOST,
    port: SSH_PORT,
    username: SSH_USER,
    password: SSH_PASSWORD,
    // Accept any host key (demo only — do NOT do this in production)
    // deno-lint-ignore require-await
    hostKeyVerifier: async () => true,
  });

  let session: SessionChannel | null = null;

  try {
    await client.connect();
    console.log("[ssh] connected to", SSH_HOST);

    // Open an interactive shell with a PTY
    session = await client.shell({
      term: "xterm-256color",
      cols: 80,
      rows: 24,
      widthPx: 0,
      heightPx: 0,
    });

    // SSH stdout ➜ WebSocket
    const pipeToWs = (async () => {
      for await (const chunk of session!.readStdout()) {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(chunk);
        }
      }
    })();

    // WebSocket ➜ SSH stdin
    ws.onmessage = async (event) => {
      if (!session) return;

      // Handle resize messages (JSON) vs. regular input (string/binary)
      if (typeof event.data === "string") {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "resize" && msg.cols && msg.rows) {
            await session.sendWindowChange(msg.cols, msg.rows, 0, 0);
            return;
          }
        } catch {
          // Not JSON — treat as regular input
        }
        await session.write(new TextEncoder().encode(event.data));
      } else if (event.data instanceof ArrayBuffer) {
        await session.write(new Uint8Array(event.data));
      }
    };

    ws.onclose = async () => {
      console.log("[ws] client disconnected");
      try {
        await session?.close();
      } catch { /* ignore */ }
      try {
        await client.disconnect();
      } catch { /* ignore */ }
    };

    // Wait for the SSH session to finish
    await pipeToWs;
  } catch (err) {
    console.error("[ssh] error:", err);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(`\r\n\x1b[31m[error] ${String(err)}\x1b[0m\r\n`);
      ws.close();
    }
  } finally {
    try { await session?.close(); } catch { /* ignore */ }
    try { await client.disconnect(); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// HTTP server — serves the frontend + upgrades to WebSocket
// ---------------------------------------------------------------------------

console.log(`Listening on http://localhost:${LISTEN_PORT}`);

Deno.serve({ port: LISTEN_PORT }, (req) => {
  const url = new URL(req.url);

  // WebSocket upgrade
  if (url.pathname === "/ws") {
    const { socket, response } = Deno.upgradeWebSocket(req);
    handleWebSocket(socket);
    return response;
  }

  // Serve the frontend
  return new Response(HTML, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
});
