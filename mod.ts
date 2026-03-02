export {
  type ClientEvents,
  type ExecResult,
  SSHClient,
  type SSHClientConfig,
} from "./src/client/ssh_client.ts";
export { SessionChannel } from "./src/connection/session_channel.ts";
export type { PtyOptions } from "./src/connection/session_channel.ts";

export {
  ServerConnection,
  type ServerConnectionEvents,
} from "./src/server/server_connection.ts";
export { ServerForwardManager } from "./src/server/server_forwarding.ts";
export {
  ServerSession,
  type SessionEvents,
} from "./src/server/server_session.ts";
export {
  type ServerEvents,
  SSHServer,
  type SSHServerConfig,
} from "./src/server/ssh_server.ts";

export { SftpClient } from "./src/sftp/sftp_client.ts";
export { SftpServer } from "./src/sftp/sftp_server.ts";
export {
  createSftpReadStream,
  createSftpWriteStream,
  pipelinedDownload,
} from "./src/sftp/sftp_stream.ts";
export {
  FileAttributes,
  type SftpDirectoryEntry,
  SftpHandle,
} from "./src/sftp/sftp_types.ts";

export type {
  AuthCredential,
  AuthProvider,
  PasswordCredential,
  PublicKeyCredential,
} from "./src/auth/auth_types.ts";

export {
  type Ed25519KeyPair,
  exportEd25519PrivateKeyPkcs8,
  exportEd25519PublicKeyRaw,
  generateEd25519KeyPair,
  importEd25519PrivateKey,
  importEd25519PublicKey,
} from "./src/crypto/ed25519.ts";

export { AgentClient } from "./src/agent/agent_client.ts";
export { AgentForwardHandler } from "./src/agent/agent_forwarding.ts";

export { Channel, ChannelState } from "./src/connection/channel.ts";
export { LocalForwardManager } from "./src/connection/forwarding_channel.ts";

export {
  DisconnectReason,
  SFTPError,
  SSHAuthError,
  SSHChannelError,
  SSHCryptoError,
  SSHDisconnectError,
  SSHError,
  SSHProtocolError,
} from "./src/utils/errors.ts";
