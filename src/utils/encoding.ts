const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8Encode(s: string): Uint8Array {
  return textEncoder.encode(s);
}

export function utf8Decode(data: Uint8Array): string {
  return textDecoder.decode(data);
}

export function hexEncode(data: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < data.length; i++) {
    hex += data[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

export function hexDecode(hex: string): Uint8Array {
  const len = hex.length >>> 1;
  const arr = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    arr[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

export function base64Encode(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]!);
  }
  return btoa(binary);
}

export function base64Decode(b64: string): Uint8Array {
  const binary = atob(b64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    arr[i] = binary.charCodeAt(i);
  }
  return arr;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const arr of arrays) totalLength += arr.length;
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
