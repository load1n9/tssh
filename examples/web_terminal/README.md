# Web Terminal — SSH-to-WebSocket Bridge

A Deno server that bridges SSH sessions to the browser using WebSockets and
[xterm.js](https://xtermjs.org/). It showcases **tssh**'s PTY allocation,
`SessionChannel`, interactive shell support, and window-change signaling.

## Architecture

```
┌──────────────┐  WebSocket   ┌──────────────┐   SSH (tssh)   ┌──────────────┐
│   Browser    │◄────────────►│  Deno Server │◄──────────────►│  SSH Server  │
│  (xterm.js)  │              │  (main.ts)   │                │              │
└──────────────┘              └──────────────┘                └──────────────┘
```

**Key tssh features demonstrated:**

- `SSHClient.shell()` — opens an interactive shell session
- `SessionChannel.requestPty()` — allocates a remote pseudo-terminal
- `SessionChannel.sendWindowChange()` — live terminal resize
- `SessionChannel.write()` / `readStdout()` — bidirectional I/O streaming

## Quick Start

```bash
# Set connection details (or edit defaults in main.ts)
export SSH_HOST=192.168.1.100
export SSH_USER=youruser
export SSH_PASSWORD=yourpassword

# Run the server
deno run --allow-net --allow-read --allow-env main.ts

# Open http://localhost:8080 in your browser
```

## Configuration

| Variable      | Default       | Description            |
|---------------|---------------|------------------------|
| `SSH_HOST`    | `127.0.0.1`  | Remote SSH server host |
| `SSH_PORT`    | `22`          | Remote SSH server port |
| `SSH_USER`    | `demo`        | SSH username           |
| `SSH_PASSWORD`| `secret`      | SSH password           |
| `LISTEN_PORT` | `8080`        | HTTP/WS listen port    |

## How It Works

1. The browser opens `http://localhost:8080` and gets served a single-page
   xterm.js terminal.
2. The page opens a WebSocket to `ws://localhost:8080/ws`.
3. The server creates a new `SSHClient`, connects to the configured SSH host,
   requests a PTY, and starts a shell.
4. Data flows bidirectionally:
   - **Keystrokes** → WebSocket → `session.write()` → SSH stdin
   - **SSH stdout** → `session.readStdout()` → WebSocket → xterm.js
5. Terminal resizes are sent as JSON messages (`{ type: "resize", cols, rows }`)
   and forwarded via `session.sendWindowChange()`.
