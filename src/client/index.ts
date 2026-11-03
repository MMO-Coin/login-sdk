// Browser-only entry: wallet generation, encryption, sessions, WebAuthn, auth client.
export {
  generateWalletBundle,
  flattenBundle,
  decryptWalletSecret,
  toSolanaKeypair,
  withDecryptedKey,
  type GenerateWalletBundleInput,
} from "./wallet.js";
export {
  setSession,
  clearSession,
  getAuthToken,
  getPublicKey,
  getEmail,
  getAppKey,
  getAuthStatus,
  getSessionState,
  captureSessionValidation,
  authHeaders,
  armAppKey,
  touchVault,
  lockVault,
  isLocked,
  subscribeLock,
  subscribeSessionState,
  subscribeSessionInvalidation,
  configureVault,
  VaultLockedError,
  SessionChangedError,
  SessionExpiredError,
} from "./session.js";
export type { AuthSessionState } from "../core/types.js";
export {
  isBiometricAvailable,
  registerPasskey,
  derivePasskeySecret,
  PrfUnavailableError,
  type PasskeyRegistration,
} from "./webauthn.js";
export {
  hasBiometricUnlock,
  enableBiometricUnlock,
  unlockViaBiometric,
  disableBiometricUnlock,
} from "./biometricUnlock.js";
export {
  AuthClient,
  createAuthClient,
  ApiError,
  type AuthClientOptions,
  type WalletGenConfig,
  type ReauthCredentials,
} from "./authClient.js";
export {
  MAX_RECOVERY_KIT_BYTES,
  parseRecoveryKit,
  serializeRecoveryKit,
  type RecoveryKit,
  type RecoveryVerification,
  type CreatedRecoveryKit,
} from "./recovery.js";
