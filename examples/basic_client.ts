import { SSHClient } from "../mod.ts";

const client = new SSHClient({
  hostname: "127.0.0.1",
  port: 2222,
  username: "demo",
  password: "secret",
  // deno-lint-ignore require-await
  hostKeyVerifier: async () => true, // Accept any host key (demo only)
});

await client.connect();
console.log("Connected!");

const result = await client.exec("whoami");
console.log("stdout:", new TextDecoder().decode(result.stdout));
console.log("exit code:", result.exitCode);

await client.disconnect();
console.log("Disconnected.");
