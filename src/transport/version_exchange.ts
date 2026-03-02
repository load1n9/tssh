import { utf8Decode, utf8Encode } from "../utils/encoding.ts";
import { SSHProtocolError } from "../utils/errors.ts";

const CR = 0x0d;
const LF = 0x0a;
const MAX_VERSION_LENGTH = 255;

export async function sendVersion(
  writer: WritableStreamDefaultWriter<Uint8Array>,
  softwareVersion: string,
): Promise<string> {
  const versionString = `SSH-2.0-${softwareVersion}`;
  const line = `${versionString}\r\n`;
  await writer.write(utf8Encode(line));
  return versionString;
}

export async function receiveVersion(
  reader: ReadableStreamDefaultReader<Uint8Array>,
): Promise<{ versionString: string; consumed: Uint8Array }> {
  const buffer: number[] = [];
  let allBytes: number[] = [];

  while (true) {
    const { value, done } = await reader.read();
    if (done || !value) {
      throw new SSHProtocolError("Connection closed during version exchange");
    }

    for (const byte of value) {
      allBytes.push(byte);
      buffer.push(byte);

      if (
        buffer.length >= 2 && buffer[buffer.length - 2] === CR &&
        buffer[buffer.length - 1] === LF
      ) {
        // Found a complete line
        const line = utf8Decode(
          new Uint8Array(buffer.slice(0, buffer.length - 2)),
        );
        buffer.length = 0;

        if (line.startsWith("SSH-")) {
          if (line.length > MAX_VERSION_LENGTH) {
            throw new SSHProtocolError("Version string too long");
          }
          if (!line.startsWith("SSH-2.0-")) {
            throw new SSHProtocolError(`Unsupported protocol version: ${line}`);
          }
          // Return any unconsumed bytes after the version line
          const consumed = new Uint8Array(allBytes);
          return { versionString: line, consumed };
        }
        // Lines not starting with SSH- are allowed before version string (RFC 4253 Section 4.2)
        allBytes = [];
      }

      if (allBytes.length > MAX_VERSION_LENGTH * 10) {
        throw new SSHProtocolError("Too much data before version string");
      }
    }
  }
}

export function parseVersionString(version: string): {
  protoVersion: string;
  softwareVersion: string;
  comments: string;
} {
  // SSH-protoversion-softwareversion SP comments
  if (!version.startsWith("SSH-")) {
    throw new SSHProtocolError(`Invalid version string: ${version}`);
  }

  const rest = version.substring(4);
  const firstDash = rest.indexOf("-");
  if (firstDash === -1) {
    throw new SSHProtocolError(`Invalid version string: ${version}`);
  }

  const protoVersion = rest.substring(0, firstDash);
  const remaining = rest.substring(firstDash + 1);

  const spaceIdx = remaining.indexOf(" ");
  if (spaceIdx === -1) {
    return { protoVersion, softwareVersion: remaining, comments: "" };
  }

  return {
    protoVersion,
    softwareVersion: remaining.substring(0, spaceIdx),
    comments: remaining.substring(spaceIdx + 1),
  };
}
