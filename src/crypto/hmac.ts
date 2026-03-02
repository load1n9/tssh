// deno-lint-ignore-file require-await
export interface HMACComputer {
  compute(data: Uint8Array): Promise<Uint8Array>;
  verify(data: Uint8Array, mac: Uint8Array): Promise<boolean>;
  readonly macLength: number;
}

export async function createHMAC(
  algorithm: "hmac-sha2-256" | "hmac-sha2-512",
  keyBytes: Uint8Array,
): Promise<HMACComputer> {
  const hashName = algorithm === "hmac-sha2-256" ? "SHA-256" : "SHA-512";
  const macLength = algorithm === "hmac-sha2-256" ? 32 : 64;

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: hashName },
    false,
    ["sign", "verify"],
  );

  return {
    macLength,

    async compute(data: Uint8Array): Promise<Uint8Array> {
      const sig = await crypto.subtle.sign(
        "HMAC",
        key,
        data as Uint8Array<ArrayBuffer>,
      );
      return new Uint8Array(sig);
    },

    async verify(data: Uint8Array, mac: Uint8Array): Promise<boolean> {
      return crypto.subtle.verify(
        "HMAC",
        key,
        mac as Uint8Array<ArrayBuffer>,
        data as Uint8Array<ArrayBuffer>,
      );
    },
  };
}
