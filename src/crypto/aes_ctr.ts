export interface AESCTRCipher {
  encrypt(plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array>;
}

export async function createAESCTRCipher(
  keyBytes: Uint8Array,
  initialIV: Uint8Array,
): Promise<AESCTRCipher> {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes as Uint8Array<ArrayBuffer>,
    "AES-CTR",
    false,
    ["encrypt", "decrypt"],
  );

  // Clone the IV so we can mutate it as a counter
  const counter = new Uint8Array(initialIV);

  function advanceCounter(blocks: number): void {
    // Treat counter as 128-bit big-endian integer, add `blocks`
    let carry = blocks;
    for (let i = 15; i >= 0 && carry > 0; i--) {
      const sum = counter[i] + (carry & 0xff);
      counter[i] = sum & 0xff;
      carry = (carry >>> 8) + (sum >>> 8);
    }
  }

  return {
    async encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
      const currentCounter = new Uint8Array(counter);
      const result = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: "AES-CTR", counter: currentCounter, length: 128 },
          key,
          plaintext as Uint8Array<ArrayBuffer>,
        ),
      );
      advanceCounter(Math.ceil(plaintext.length / 16));
      return result;
    },

    async decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
      const currentCounter = new Uint8Array(counter);
      const result = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-CTR", counter: currentCounter, length: 128 },
          key,
          ciphertext as Uint8Array<ArrayBuffer>,
        ),
      );
      advanceCounter(Math.ceil(ciphertext.length / 16));
      return result;
    },
  };
}
