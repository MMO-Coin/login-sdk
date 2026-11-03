// Portable recovery wraps the existing encryption key. It never generates wallets,
// changes derivation inputs, or writes a replacement account to the server.
import { Keypair } from "@solana/web3.js";
import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";
import { decryptSecret, encryptSecret, randomHex } from "../core/crypto.js";
import type { EncryptedWallet, UserData } from "../core/types.js";
import { deriveAuthPublicKey } from "./authKey.js";

export const MAX_RECOVERY_KIT_BYTES = 65_536;
const FORMAT = "mmo-login-recovery";
const CIPHERTEXT = /^[A-Za-z0-9_-]{16}:[A-Za-z0-9_-]{22,}$/;
const HEX_KEY = /^[0-9a-f]{64}$/i;

/** Keep this encrypted file and its independently generated code separately. */
export interface RecoveryKit {
  format: "mmo-login-recovery";
  version: 1;
  ciphertext: string;
}

/** Safe to display after successful local verification. No signing key is returned. */
export interface RecoveryVerification {
  appId: string;
  origin: string;
  createdAt: number;
  publicKey: string;
  email: string;
  authMethod: "email" | "biometric";
  wallets: Array<Pick<EncryptedWallet, "chain" | "role" | "publicKey">>;
}

export interface CreatedRecoveryKit {
  kit: RecoveryKit;
  recoveryCode: string;
  verification: RecoveryVerification;
}

interface RecoveryUser {
  appId: string;
  publicKey: string;
  email: string;
  authMethod: "email" | "biometric";
  authPublicKey: string;
  pbkdf2Iterations?: number;
  wallets: EncryptedWallet[];
}

/** Internal decrypted content. Never expose this from a public verification result. */
export interface RecoveryPayload {
  format: "mmo-login-recovery";
  version: 1;
  origin: string;
  createdAt: number;
  appKey: string;
  user: RecoveryUser;
}

function invalid(message = "Invalid recovery kit"): never {
  throw new Error(message);
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalid();
  // Response.json() and files can come from another realm. Validate their own
  // fields below instead of comparing realm-specific Object prototypes.
  if (Object.prototype.toString.call(value) !== "[object Object]") return invalid();
  return value as Record<string, unknown>;
}

function keys(value: Record<string, unknown>, required: string[], optional: string[] = []): void {
  if (required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) invalid();
  if (Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))) invalid();
}

function boundedText(value: unknown, max: number): string {
  if (typeof value !== "string" || !value.length || value.length > max) return invalid();
  return value;
}

function canonicalOrigin(value: unknown): string {
  const text = boundedText(value, 2_048);
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return invalid();
  }
  if (!["https:", "http:"].includes(url.protocol) || url.origin !== text) return invalid();
  return text;
}

function parseWallets(value: unknown): EncryptedWallet[] {
  if (!Array.isArray(value) || !value.length || value.length > 4) return invalid();
  const slots = new Set<string>();
  return value.map((entry) => {
    const wallet = record(entry);
    keys(wallet, ["chain", "role", "publicKey", "encryptedSecret"]);
    if (wallet.chain !== "solana" && wallet.chain !== "evm") return invalid();
    if (wallet.role !== "funds" && wallet.role !== "signing") return invalid();
    const slot = `${wallet.chain}:${wallet.role}`;
    if (slots.has(slot)) return invalid();
    slots.add(slot);
    const publicKey = boundedText(wallet.publicKey, 64);
    const encryptedSecret = boundedText(wallet.encryptedSecret, 2_048);
    if (!CIPHERTEXT.test(encryptedSecret)) return invalid();
    return { chain: wallet.chain, role: wallet.role, publicKey, encryptedSecret };
  });
}

function parseUser(value: unknown): RecoveryUser {
  const user = record(value);
  keys(user, ["appId", "publicKey", "email", "authMethod", "authPublicKey", "wallets"], ["pbkdf2Iterations"]);
  const appId = boundedText(user.appId, 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(appId)) return invalid();
  const publicKey = boundedText(user.publicKey, 64);
  const email = boundedText(user.email, 320);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email !== email.toLowerCase().trim()) return invalid();
  if (user.authMethod !== "email" && user.authMethod !== "biometric") return invalid();
  const authPublicKey = boundedText(user.authPublicKey, 64);
  if (!HEX_KEY.test(authPublicKey)) return invalid();
  if (
    user.pbkdf2Iterations !== undefined &&
    (!Number.isSafeInteger(user.pbkdf2Iterations) ||
      (user.pbkdf2Iterations as number) < 1 ||
      (user.pbkdf2Iterations as number) > 10_000_000)
  )
    return invalid();
  const wallets = parseWallets(user.wallets);
  if (!wallets.some((wallet) => wallet.publicKey === publicKey)) return invalid();
  return {
    appId,
    publicKey,
    email,
    authMethod: user.authMethod,
    authPublicKey,
    wallets,
    ...(user.pbkdf2Iterations !== undefined ? { pbkdf2Iterations: user.pbkdf2Iterations as number } : {}),
  };
}

/** Parse a bounded versioned file before attempting any decryption or network request. */
export function parseRecoveryKit(value: unknown): RecoveryKit {
  let input = value;
  if (typeof input === "string") {
    if (
      input.length > MAX_RECOVERY_KIT_BYTES ||
      new TextEncoder().encode(input).byteLength > MAX_RECOVERY_KIT_BYTES
    )
      return invalid("Recovery kit is too large");
    try {
      input = JSON.parse(input);
    } catch {
      return invalid();
    }
  }
  const kit = record(input);
  keys(kit, ["format", "version", "ciphertext"]);
  if (kit.format !== FORMAT || kit.version !== 1)
    return invalid("Unsupported recovery kit format or version");
  const ciphertext = boundedText(kit.ciphertext, MAX_RECOVERY_KIT_BYTES - 128);
  if (!CIPHERTEXT.test(ciphertext)) return invalid();
  return { format: FORMAT, version: 1, ciphertext };
}

export function serializeRecoveryKit(kit: RecoveryKit): string {
  const text = JSON.stringify(parseRecoveryKit(kit), null, 2);
  if (new TextEncoder().encode(text).byteLength > MAX_RECOVERY_KIT_BYTES)
    return invalid("Recovery kit is too large");
  return `${text}\n`;
}

function recoveryKey(code: string): string {
  if (typeof code !== "string" || code.length > 160) return invalid("Invalid recovery code");
  const compact = code.replace(/[\s-]/g, "");
  if (!/^MMO1[0-9a-f]{64}$/i.test(compact)) return invalid("Enter the complete generated recovery code");
  return compact.slice(4).toLowerCase();
}

function verification(payload: RecoveryPayload): RecoveryVerification {
  return {
    appId: payload.user.appId,
    origin: payload.origin,
    createdAt: payload.createdAt,
    publicKey: payload.user.publicKey,
    email: payload.user.email,
    authMethod: payload.user.authMethod,
    wallets: payload.user.wallets.map(({ chain, role, publicKey }) => ({ chain, role, publicKey })),
  };
}

/** Cryptographically check every saved secret against its stated public address. */
export async function verifyRecoveryWallets(wallets: EncryptedWallet[], appKey: string): Promise<void> {
  for (const wallet of parseWallets(wallets)) {
    const secret = await decryptSecret(wallet.encryptedSecret, appKey);
    if (wallet.chain === "solana") {
      if (!/^[0-9a-f]{128}$/i.test(secret)) return invalid("Recovery wallet verification failed");
      const bytes = Uint8Array.from(secret.match(/.{2}/g)!, (hex) => parseInt(hex, 16));
      let pair: Keypair | undefined;
      try {
        pair = Keypair.fromSecretKey(bytes);
        if (pair.publicKey.toBase58() !== wallet.publicKey)
          return invalid("Recovery wallet address does not match");
      } finally {
        bytes.fill(0);
        pair?.secretKey.fill(0);
      }
    } else {
      if (!/^0x[0-9a-f]{64}$/i.test(secret)) return invalid("Recovery wallet verification failed");
      if (privateKeyToAccount(secret as Hex).address.toLowerCase() !== wallet.publicKey.toLowerCase())
        return invalid("Recovery wallet address does not match");
    }
  }
}

export async function createEncryptedRecoveryKit(
  user: UserData,
  appKey: string,
  origin: string,
): Promise<CreatedRecoveryKit> {
  if (user.authMethod === "wallet")
    throw new Error("External wallet accounts must use their original wallet recovery method");
  const savedUser = parseUser({
    appId: user.appId,
    publicKey: user.publicKey,
    email: user.email?.toLowerCase().trim(),
    authMethod: user.authMethod,
    authPublicKey: user.authPublicKey,
    wallets: user.wallets,
    ...(user.pbkdf2Iterations !== undefined ? { pbkdf2Iterations: user.pbkdf2Iterations } : {}),
  });
  if (!HEX_KEY.test(appKey) || deriveAuthPublicKey(appKey) !== savedUser.authPublicKey)
    throw new Error("Re-authentication failed: wrong credentials");
  await verifyRecoveryWallets(savedUser.wallets, appKey);
  const payload: RecoveryPayload = {
    format: FORMAT,
    version: 1,
    origin: canonicalOrigin(origin),
    createdAt: Date.now(),
    appKey,
    user: savedUser,
  };
  const key = randomHex(32);
  const kit: RecoveryKit = {
    format: FORMAT,
    version: 1,
    ciphertext: await encryptSecret(JSON.stringify(payload), key),
  };
  serializeRecoveryKit(kit);
  const recoveryCode = `MMO1-${key.toUpperCase().match(/.{8}/g)!.join("-")}`;
  return { kit, recoveryCode, verification: verification(payload) };
}

/** Internal open operation. The public client returns only verification metadata. */
export async function openRecoveryKit(
  input: unknown,
  code: string,
  appId: string,
  origin: string,
): Promise<{ payload: RecoveryPayload; verification: RecoveryVerification }> {
  const kit = parseRecoveryKit(input);
  let plain: string;
  try {
    plain = await decryptSecret(kit.ciphertext, recoveryKey(code));
  } catch {
    throw new Error("Recovery code is incorrect or the kit is damaged");
  }
  if (plain.length > MAX_RECOVERY_KIT_BYTES) return invalid();
  let decoded: unknown;
  try {
    decoded = JSON.parse(plain);
  } catch {
    return invalid();
  }
  const value = record(decoded);
  keys(value, ["format", "version", "origin", "createdAt", "appKey", "user"]);
  if (value.format !== FORMAT || value.version !== 1)
    return invalid("Unsupported recovery kit format or version");
  const savedOrigin = canonicalOrigin(value.origin);
  const user = parseUser(value.user);
  if (savedOrigin !== canonicalOrigin(origin) || user.appId !== appId)
    throw new Error("This recovery kit belongs to another app or site");
  if (
    !Number.isSafeInteger(value.createdAt) ||
    (value.createdAt as number) < 1 ||
    (value.createdAt as number) > Date.now() + 300_000
  )
    return invalid();
  const appKey = boundedText(value.appKey, 64);
  if (!HEX_KEY.test(appKey) || deriveAuthPublicKey(appKey) !== user.authPublicKey)
    return invalid("Recovery identity verification failed");
  await verifyRecoveryWallets(user.wallets, appKey);
  const payload: RecoveryPayload = {
    format: FORMAT,
    version: 1,
    origin: savedOrigin,
    createdAt: value.createdAt as number,
    appKey,
    user,
  };
  return { payload, verification: verification(payload) };
}

/** A stale backup cannot silently restore a different account or replaced wallet slot. */
export async function verifyRecoveredUser(current: UserData, payload: RecoveryPayload): Promise<void> {
  const saved = payload.user;
  if (
    current.appId !== saved.appId ||
    current.publicKey !== saved.publicKey ||
    current.email?.toLowerCase().trim() !== saved.email ||
    current.authMethod !== saved.authMethod ||
    current.authPublicKey !== saved.authPublicKey ||
    current.pbkdf2Iterations !== saved.pbkdf2Iterations
  )
    throw new Error("The server account does not match this recovery kit");
  const wallets = parseWallets(current.wallets);
  for (const backedUp of saved.wallets) {
    const live = wallets.find((wallet) => wallet.chain === backedUp.chain && wallet.role === backedUp.role);
    const equal =
      live &&
      (backedUp.chain === "evm"
        ? live.publicKey.toLowerCase() === backedUp.publicKey.toLowerCase()
        : live.publicKey === backedUp.publicKey);
    if (!equal) throw new Error("A wallet changed since this recovery kit was created. Use a current backup");
  }
  await verifyRecoveryWallets(wallets, payload.appKey);
}
