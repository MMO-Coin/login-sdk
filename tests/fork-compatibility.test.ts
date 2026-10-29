import fixture from "./fixtures/tetrac-0.6.0.json";
import {
  APP_ID_HEADER,
  AUTH_TOKEN_HEADER,
  PUBLIC_KEY_HEADER,
  decryptSecret,
  deriveAppKeyFromPasskey,
  walletAppKeyMessage,
  walletAppKeyMessageHw,
} from "../src/core/index";
import { deriveAuthPublicKey } from "../src/client/authKey";

// Generated once by the original 0.6.0 package with public test data.
// Keep these values fixed so a package rename cannot silently change wallet recovery.
describe("existing terminal wallets", () => {
  it("derives the same encryption and authentication keys", () => {
    const appKey = deriveAppKeyFromPasskey(
      fixture.passphrase,
      fixture.email,
      fixture.iterations,
      fixture.appId,
    );
    expect(appKey).toBe(fixture.appKey);
    expect(deriveAuthPublicKey(appKey)).toBe(fixture.authPublicKey);
  });

  it("decrypts a wallet secret encrypted by version 0.6.0", async () => {
    await expect(decryptSecret(fixture.ciphertext, fixture.appKey)).resolves.toBe(fixture.secret);
  });

  it("preserves the signed wallet recovery messages", () => {
    expect(walletAppKeyMessage(fixture.appId, fixture.origin)).toBe(fixture.walletMessage);
    expect(walletAppKeyMessageHw(fixture.appId, fixture.origin)).toBe(fixture.hardwareWalletMessage);
  });

  it("preserves the authentication headers", () => {
    expect({ appId: APP_ID_HEADER, authToken: AUTH_TOKEN_HEADER, publicKey: PUBLIC_KEY_HEADER }).toEqual(
      fixture.headers,
    );
  });
});
