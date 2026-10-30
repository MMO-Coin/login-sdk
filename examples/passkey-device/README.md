# Real-device passkey checks

Use this page to check the built SDK on physical authenticators. Automated Chromium results are separate from physical-device results.

## Start on this computer

Use a dedicated QA origin with no other application or existing accounts on it.

~~~sh
npm ci
npm run qa:passkeys
~~~

Open http://localhost:4194 in a normal browser window. Complete Windows Hello, PIN, fingerprint or face prompts yourself. The platform authenticator must be set up in the operating system first.

The server binds only to 127.0.0.1. It uses MemoryAdapter and fresh, synthetic email addresses with a public test passphrase. The page creates two unfunded wallet records for each test account. Account data disappears when the server stops. It has no database connection settings.

The QA vault locks when the page is hidden and after five minutes of inactivity. The longer timeout gives a person time to work through the checklist.

## Phone access

A phone needs a dedicated HTTPS hostname with a certificate the phone trusts. A computer's localhost URL refers to that phone when opened on the phone. Plain HTTP over a LAN address does not provide the secure context WebAuthn needs.

Run the server behind your HTTPS reverse proxy:

~~~sh
npm run qa:passkeys -- --origin https://qa.example.test --port 4194
~~~

Forward that origin to http://127.0.0.1:4194 on the same host and preserve the public Host header. For example, inside an existing HTTPS nginx server block:

~~~nginx
location / {
    proxy_pass http://127.0.0.1:4194;
    proxy_set_header Host $http_host;
}
~~~

The server checks Host and Origin and rejects cross-site requests. Keep this QA service on its own origin. Its SDK session storage keys are shared within an origin.

See [MDN secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Secure_Contexts) and [WebAuthn](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API).

## Checklist

Use a fresh run for each browser and authenticator combination. Suggested targets are Windows Hello in a desktop browser, Android Chrome and iPhone Safari. Record unsupported devices as unsupported.

| Step | Action | Expected result |
|---|---|---|
| 1 | Create synthetic email wallet | Email registration passes. |
| 2 | Enable passkey unlock and complete the device prompts | PRF unlock is enabled, or the result clearly says unsupported. |
| 3 | Lock wallet, then unlock with passkey | The same wallet key and wallet records return. |
| 4 | Reload while unlocked, then unlock | Reload starts locked; the same key returns after the prompt. |
| 5 | Lock wallet, select Test cancellation, then dismiss the prompt | The wallet stays locked. Accepting the prompt does not count as a cancellation pass. |
| 6 | Unlock, select Check background lock, switch to another app, then return | The wallet is locked when you return. |
| 7 | Unlock again, then disable passkey unlock | The on-device unlock registration is removed. |
| 8 | Sign out | The local key is cleared and the old server token is rejected. |
| 9 | Create passkey account | A separate synthetic account is created using PRF. |
| 10 | Sign out, then sign in with saved passkey | The same account key and wallet records return. |
| 11 | Sign out and download the report | Both sessions have been revoked; the report reflects the checks you actually ran. |

Registration can show more than one prompt because credential creation and PRF assertion are separate operations.

An authenticator being available does not prove PRF support. If registration reports PrfUnavailableError, record the unsupported result. The SDK keeps its fail-closed behavior. A browser or authenticator that rejects the operation must not receive a weaker stored-key fallback.

If the server restarts, select Reset this QA run and start again. Non-secret test state survives a page reload in the same tab. Closing the tab starts a new report.

## Reports and cleanup

Reports are downloaded locally. They contain the SDK version, browser family and major version, coarse platform, capability flags and check results. They exclude account identifiers, wallet addresses, key fingerprints, keys, tokens and credential descriptors. The page sends no report to the server.

A report is incomplete while a check is unrun. Automated browsers are labelled automated. A virtual-authenticator result must not be presented as a physical-device result.

Save reports under output/passkey-device/ if you keep them in this checkout. That directory is ignored by Git.

After testing:

1. Sign out and reset the QA run.
2. Remove credentials named SDK QA from your device's passkey manager. Resetting the page cannot remove device-saved passkeys.
3. Stop the QA server when finished.

~~~sh
npm run test:passkeys
npm run verify
~~~

The browser suite checks the QA controls, cancellation, reload continuity, unsupported PRF, redacted report export and origin protections. Physical-device prompts still require a person.
