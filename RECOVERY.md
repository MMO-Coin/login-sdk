# Encrypted wallet recovery

Recovery kits let an existing email or biometric account sign in without its original passphrase or passkey device. A kit preserves the account's encryption key and encrypted wallet records. It does not generate replacement wallets or change existing addresses.

The encrypted JSON file and its generated recovery code are both required. The code contains 256 random bits. It is not a password or a PIN. Keep the file and code separately, outside the browser, and do not send either to support staff. Anyone who obtains both can access the saved wallets. A downloaded kit cannot be revoked by logging out or creating another kit.

## Create and verify a backup

Use a current authenticated account and require fresh credentials to create a kit. The creation call checks every encrypted wallet against its public address. It does not unlock a locked vault or extend an unlocked session.

```ts
import { serializeRecoveryKit } from "@mmo-coin/login-sdk/client";

const backup = await client.createRecoveryKit({ passkey: enteredPassphrase });
const encryptedFile = serializeRecoveryKit(backup.kit);
// Offer encryptedFile as a local JSON download. Show backup.recoveryCode separately.
// Never save the code, passphrase or decrypted key to browser storage or logs.
```

Ask the person to select the downloaded file and enter the saved code before marking a backup as verified. Compare the selected file with the created kit and show the verified addresses.

```ts
const checked = await client.verifyRecoveryKit(selectedFileText, enteredRecoveryCode);
// checked.wallets contains only { chain, role, publicKey } entries.
// Local verification does not contact the server or unlock the wallet.
```

Files are versioned and limited to `MAX_RECOVERY_KIT_BYTES` (64 KiB). Reject oversized files before reading them in a browser. Both the file and its encrypted payload are validated. A wrong code, changed ciphertext, wrong app/site, invalid schema or mismatched wallet address fails closed.

## Sign in with a recovery kit

```ts
const controller = new AbortController();
const result = await client.recoverWithKit({
  kit: selectedFileText,
  recoveryCode: enteredRecoveryCode,
  signal: controller.signal,
});
// Abort on dialog close, navigation or changed inputs. Discard all secret UI state.
```

Recovery first checks the file locally. It then proves control of the original authentication key through the existing single-use challenge/login routes. Before saving the new browser session, it checks the current server account and all wallet addresses against the backup. A missing account or a replaced wallet slot is refused. Additional wallet slots must decrypt correctly under the same key.

The current server database must remain available for this sign-in flow. The SDK does not register a new account, overwrite server wallet records or reset the passphrase. After a reload or local lock, a person who no longer has their original credentials can sign in with the file and code again. Keep the original passphrase or device when it is still available. External-wallet accounts continue to use the original wallet provider's recovery process.

## Backup scope and compatibility

- The kit includes the existing app key and encrypted SDK wallet snapshot. It excludes session tokens, plaintext private keys, browser-local exchange API keys, pending transfers and venue authorizations.
- Local verification confirms the saved wallet keys and addresses. It does not establish that an exchange account, open order or deposit has been restored. Applications must reconcile those separately and reauthorize a venue when needed.
- The kit is bound to the original `appId` and browser origin. Keep these values, the original database and all existing derivation inputs stable when upgrading.
- Recovery does not replace operational database backups. Keep encrypted, tested server backups as well. If the service or record is lost, this login API does not recreate it from a file.
- No recovery kit can recover a wallet after all its credentials and backups are already lost. Offer backup creation while the person can still authenticate.

Recovery and verification do not silently arm a key after logout, account change, local lock or an aborted operation. Applications should clear the file, code and displayed backup data on those events and on dialog close. The SDK returns public verification metadata only; decrypted recovery material remains internal to the operation. JavaScript strings cannot be reliably zeroed, so keep these operations and their UI lifetime short.
