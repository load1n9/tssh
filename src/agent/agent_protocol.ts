import { utf8Decode } from "../utils/encoding.ts";
import * as AC from "./agent_constants.ts";

export interface AgentIdentity {
  publicKeyBlob: Uint8Array;
  comment: string;
}

/** Encode SSH_AGENTC_REQUEST_IDENTITIES message */
export function encodeRequestIdentities(): Uint8Array {
  const packet = new Uint8Array(5);
  new DataView(packet.buffer).setUint32(0, 1);
  packet[4] = AC.SSH_AGENTC_REQUEST_IDENTITIES;
  return packet;
}

/** Decode SSH_AGENT_IDENTITIES_ANSWER message */
export function decodeIdentitiesAnswer(data: Uint8Array): AgentIdentity[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  // Skip length (4 bytes)
  offset += 4;
  // Skip type (1 byte)
  const type = data[offset++];
  if (type !== AC.SSH_AGENT_IDENTITIES_ANSWER) {
    throw new Error(
      `Expected IDENTITIES_ANSWER (${AC.SSH_AGENT_IDENTITIES_ANSWER}), got ${type}`,
    );
  }

  const count = view.getUint32(offset);
  offset += 4;
  const identities: AgentIdentity[] = [];

  for (let i = 0; i < count; i++) {
    const blobLen = view.getUint32(offset);
    offset += 4;
    const publicKeyBlob = data.slice(offset, offset + blobLen);
    offset += blobLen;
    const commentLen = view.getUint32(offset);
    offset += 4;
    const comment = utf8Decode(data.slice(offset, offset + commentLen));
    offset += commentLen;
    identities.push({ publicKeyBlob, comment });
  }

  return identities;
}

/** Encode SSH_AGENTC_SIGN_REQUEST message */
export function encodeSignRequest(
  publicKeyBlob: Uint8Array,
  data: Uint8Array,
  flags: number = 0,
): Uint8Array {
  const payloadLen = 1 + 4 + publicKeyBlob.length + 4 + data.length + 4;
  const packet = new Uint8Array(4 + payloadLen);
  const view = new DataView(packet.buffer);
  let offset = 0;

  view.setUint32(offset, payloadLen);
  offset += 4;
  packet[offset++] = AC.SSH_AGENTC_SIGN_REQUEST;
  view.setUint32(offset, publicKeyBlob.length);
  offset += 4;
  packet.set(publicKeyBlob, offset);
  offset += publicKeyBlob.length;
  view.setUint32(offset, data.length);
  offset += 4;
  packet.set(data, offset);
  offset += data.length;
  view.setUint32(offset, flags);

  return packet;
}

/** Decode SSH_AGENT_SIGN_RESPONSE message */
export function decodeSignResponse(data: Uint8Array): Uint8Array {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  // Skip length
  offset += 4;
  const type = data[offset++];
  if (type !== AC.SSH_AGENT_SIGN_RESPONSE) {
    throw new Error(
      `Expected SIGN_RESPONSE (${AC.SSH_AGENT_SIGN_RESPONSE}), got ${type}`,
    );
  }

  const sigLen = view.getUint32(offset);
  offset += 4;
  return data.slice(offset, offset + sigLen);
}
