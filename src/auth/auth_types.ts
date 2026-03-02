import type { Ed25519KeyPair } from "../crypto/ed25519.ts";

export interface PasswordCredential {
  method: "password";
  username: string;
  password: string;
}

export interface PublicKeyCredential {
  method: "publickey";
  username: string;
  keyPair: Ed25519KeyPair;
}

export type AuthCredential = PasswordCredential | PublicKeyCredential;

export interface AuthProvider {
  authenticatePassword(username: string, password: string): Promise<boolean>;
  authenticatePublicKey(
    username: string,
    publicKeyBlob: Uint8Array,
  ): Promise<boolean>;
  getAllowedMethods(username: string): Promise<string[]>;
}
