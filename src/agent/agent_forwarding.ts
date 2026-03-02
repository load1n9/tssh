import type { Channel } from "../connection/channel.ts";

/**
 * Handles agent forwarding on the client side.
 * When the server opens an auth-agent@openssh.com channel,
 * this relays data to the local SSH agent socket.
 */
export class AgentForwardHandler {
  #agentSocketPath: string;

  constructor(agentSocketPath?: string) {
    this.#agentSocketPath = agentSocketPath ?? Deno.env.get("SSH_AUTH_SOCK") ??
      "";
  }

  /** Request agent forwarding on a session channel */
  // deno-lint-ignore require-await
  async requestForwarding(channel: Channel): Promise<boolean> {
    return channel.sendRequest("auth-agent-req@openssh.com", true);
  }

  /** Handle an incoming auth-agent@openssh.com channel by relaying to local agent */
  async handleAgentChannel(channel: Channel): Promise<void> {
    if (!this.#agentSocketPath) {
      await channel.close();
      return;
    }

    try {
      // Connect to local agent socket
      // deno-lint-ignore no-explicit-any
      const agentConn: any = await (Deno.connect as any)({
        path: this.#agentSocketPath,
        transport: "unix",
      });

      // Bidirectional pipe
      const channelToAgent = (async () => {
        try {
          const writer = agentConn.writable.getWriter();
          for await (const data of channel.readData()) {
            await writer.write(data);
          }
          await writer.close();
        } catch (_) {
          /* Connection closed */
        }
      })();

      const agentToChannel = (async () => {
        try {
          const reader = agentConn.readable.getReader();
          while (true) {
            const { value, done } = await reader.read();
            if (done || !value) break;
            await channel.write(value);
          }
          await channel.sendEof();
        } catch (_) {
          /* Connection closed */
        }
      })();

      await Promise.allSettled([channelToAgent, agentToChannel]);
    } catch (_) {
      // Could not connect to agent
      await channel.close();
    }
  }
}
