# PGP Manager

A simple local PGP workspace, built with React, Vite, Node.js, Express, and [OpenPGP.js](https://docs.openpgpjs.org/). Import and organize public/private keys, create key pairs, and encrypt or decrypt text messages.

## Run

Requires Node.js 22.12 or newer (Node 24 is used here).

```sh
npm install
npm run dev
```

Open **http://127.0.0.1:3419**. Vite provides hot reload through the Node server; there is a single application port. The development HMR websocket uses port 3420. On macOS, Node watches the `server` folder for backend changes.

For the built application:

```sh
npm run build
npm start
```

`npm test` runs isolated integration tests, including PGP round trips, disk persistence, origin protections, signature verification, and GnuPG compatibility when `gpg` is installed. Test keys are created in temporary directories, never in your real vault.

## Use

1. Open **Keys** and import an armored `.asc` key or generate a key pair. The import dialog has separate public and private key fields: fill either one or both. When both are supplied, they must be a matching pair. A private key includes its public key, so you can import it by itself. Importing the matching private key upgrades an existing public key without creating a duplicate. Optional passphrase and fingerprint fields are available during import and in key details. The passphrase unlocks protected key material once and is not saved; the supplied fingerprint must match the key.
2. To **encrypt**, choose the recipient’s public key, write your message, and copy or download the encrypted result.
3. To **decrypt**, choose your private key, paste the complete PGP message, and click Decrypt. Signed messages are checked against the public keys in your vault; unknown or invalid signatures are explicitly flagged.
4. Use **Copy public key** on a key card or in its details to copy the complete armored public key for sharing. Details also let you export public/private keys. Generated keys have an exportable revocation certificate. Deleting a key removes it locally; it does not revoke it.

## Local storage

- Keys are stored in **`data/keys.json`**, excluded from Git. The directory has `0700` permissions and the file has `0600` permissions on macOS/Linux. Writes are serialized and atomically replace the file.
- Private keys are stored and exported **unencrypted**. Import your PGP key as-is. If the file already has passphrase protection, import asks for its existing passphrase once and saves the unlocked key; messages never need it again. Previously encrypted keys remain available for encryption and export until you reimport and unlock them. Previously saved unlocked copies are converted to the main unencrypted private key automatically.
- Plaintext and encrypted messages are not saved or logged. They are processed in memory by the local Node server. UI drafts last only until the page reloads.
- All fonts and assets are served locally. The application makes no requests to external services.
- The server binds to **127.0.0.1** and rejects non-local Host headers and cross-origin browser requests. This is a local single-user application without account authentication; do not expose it over a network or reverse proxy.
- Export your private keys and revocation certificates for backups and keep them somewhere safe.

Set `PGP_DATA_DIR` to an absolute directory to move the vault, or set `PORT` to change the application port. Stop the application before moving or replacing a vault. Run one server per vault directory.

## PM2 Manager

The saved **PGP Manager** server uses this project folder, port **3419**, and launch command **`npm run dev`**. Vite automatically updates the open page after frontend edits; Node restarts after changes in `server/`. There is no need to rebuild or manually reload for routine edits. `npm run build` and `npm start` remain available for running a production build.
