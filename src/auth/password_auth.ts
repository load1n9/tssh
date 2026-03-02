import { SSHBufferReader } from "../protocol/buffer_reader.ts";
import { SSHBufferWriter } from "../protocol/buffer_writer.ts";

/** Build method-specific data for password authentication*/
export function buildPasswordAuthData(password: string): Uint8Array {
  const w = new SSHBufferWriter(128);
  w.writeBoolean(false);
  w.writeStringFromUTF8(password);
  return w.toBytes();
}

/** Parse method-specific data for password authentication on server side */
export function parsePasswordAuthData(data: Uint8Array): {
  changePassword: boolean;
  password: string;
  newPassword?: string;
} {
  const r = new SSHBufferReader(data);
  const changePassword = r.readBoolean();
  const password = r.readStringAsUTF8();
  const newPassword = changePassword && r.remaining() > 0
    ? r.readStringAsUTF8()
    : undefined;
  return { changePassword, password, newPassword };
}
