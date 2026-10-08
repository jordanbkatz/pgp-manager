import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import http from "node:http";
import * as openpgp from "openpgp";
import { createApp } from "../server/app.js";

const passphrase = "test-only-long-passphrase";
const message =
  "A private note.\nUnicode: café, 日本語, 🔐\n  Keep the spacing.  ";
const fixture = await openpgp.generateKey({
  type: "ecc",
  curve: "curve25519",
  userIDs: [{ name: "Test Recipient", email: "recipient@example.com" }],
});
const second = await openpgp.generateKey({
  type: "ecc",
  curve: "curve25519",
  userIDs: [{ name: "Test Sender", email: "sender@example.com" }],
});

async function workspace(t, directory) {
  const dataDirectory =
    directory || (await mkdtemp(path.join(os.tmpdir(), "cipher-test-")));
  const app = await createApp({ dataDirectory });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    if (!directory) await rm(dataDirectory, { recursive: true, force: true });
  });
  return {
    dataDirectory,
    base,
    async request(route, body, method = body ? "POST" : "GET", headers = {}) {
      const response = await fetch(`${base}/api${route}`, {
        method,
        headers: { "Content-Type": "application/json", ...headers },
        body: body ? JSON.stringify(body) : undefined,
      });
      return {
        status: response.status,
        headers: response.headers,
        data: response.status === 204 ? null : await response.json(),
      };
    },
  };
}
async function importKey(client, armoredKey = fixture.privateKey) {
  const response = await client.request("/keys/import", { armoredKey });
  assert.equal(response.status, 201, response.data.error);
  return response.data.key;
}

test("imports a private key alone through the private field and enables encryption and decryption", async (t) => {
  const client = await workspace(t);
  const imported = await client.request("/keys/import", {
    publicKey: "",
    privateKey: fixture.privateKey,
  });
  assert.equal(imported.status, 201, imported.data.error);
  const key = imported.data.key;
  assert.equal(key.hasPrivate, true);
  assert.equal(key.readyToDecrypt, true);
  assert.equal(key.canEncrypt, true);
  const encrypted = await client.request("/encrypt", {
    keyId: key.id,
    message,
  });
  const decrypted = await client.request("/decrypt", {
    keyId: key.id,
    message: encrypted.data.message,
  });
  assert.equal(decrypted.status, 200, decrypted.data.error);
  assert.equal(decrypted.data.message, message);
});

test("imports a matching public/private pair as one record and upgrades public-only imports", async (t) => {
  const client = await workspace(t);
  const publicOnly = await client.request("/keys/import", {
    publicKey: fixture.publicKey,
    privateKey: "",
  });
  assert.equal(publicOnly.status, 201, publicOnly.data.error);
  assert.equal(publicOnly.data.key.hasPrivate, false);
  const pair = await client.request("/keys/import", {
    publicKey: fixture.publicKey,
    privateKey: fixture.privateKey,
    label: "My imported pair",
  });
  assert.equal(pair.status, 201, pair.data.error);
  assert.equal(pair.data.key.id, publicOnly.data.key.id);
  assert.equal(pair.data.key.hasPrivate, true);
  assert.equal(pair.data.key.readyToDecrypt, true);
  assert.equal(pair.data.key.name, "My imported pair");
  assert.equal((await client.request("/keys")).data.keys.length, 1);
  const exported = await client.request(
    `/keys/${pair.data.key.id}/export?type=private`,
  );
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: exported.data.armoredKey,
  });
  assert.equal(privateKey.isDecrypted(), true);
});

test("rejects mismatched pairs and invalid optional key fields without saving partial records", async (t) => {
  const client = await workspace(t);
  const requests = [
    { publicKey: second.publicKey, privateKey: fixture.privateKey },
    { publicKey: fixture.publicKey, privateKey: "broken private key" },
    { publicKey: "", privateKey: "" },
    { publicKey: fixture.privateKey, privateKey: "" },
    { publicKey: "", privateKey: fixture.publicKey },
    { publicKey: [], privateKey: fixture.privateKey },
  ];
  for (const body of requests) {
    const response = await client.request("/keys/import", body);
    assert.equal(response.status, 400, response.data.error);
    assert.equal((await client.request("/keys")).data.keys.length, 0);
  }
});

test("generates unencrypted keys and persists only armored material with restricted permissions", async (t) => {
  const client = await workspace(t);
  const response = await client.request("/keys/generate", {
    name: "Local User",
    email: "local@example.com",
  });
  assert.equal(response.status, 201, response.data.error);
  assert.equal(response.data.key.readyToDecrypt, true);
  assert.equal(response.data.key.hasPrivate, true);
  assert.equal(response.data.key.hasRevocation, true);
  assert.equal(response.data.key.privateKey, undefined);
  const saved = await readFile(
    path.join(client.dataDirectory, "keys.json"),
    "utf8",
  );
  assert.ok(saved.includes("BEGIN PGP PRIVATE KEY BLOCK"));
  assert.ok(!saved.includes(passphrase));
  assert.equal((await stat(client.dataDirectory)).mode & 0o777, 0o700);
  assert.equal(
    (await stat(path.join(client.dataDirectory, "keys.json"))).mode & 0o777,
    0o600,
  );
  const exported = await client.request(
    `/keys/${response.data.key.id}/export?type=revocation`,
  );
  assert.match(exported.data.armoredKey, /BEGIN PGP PUBLIC KEY BLOCK/);
});

test("imports protected private keys with a one-time unlock and saves them unencrypted", async (t) => {
  const client = await workspace(t);
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: fixture.privateKey,
  });
  const encrypted = (
    await openpgp.encryptKey({ privateKey, passphrase })
  ).armor();
  const response = await client.request("/keys/import", {
    privateKey: encrypted,
  });
  assert.equal(response.status, 400);
  assert.equal(response.data.code, "KEY_PASSPHRASE_REQUIRED");
  const wrong = await client.request("/keys/import", {
    privateKey: encrypted,
    passphrase: "wrong",
  });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.data.code, "KEY_PASSPHRASE_REQUIRED");
  assert.equal((await client.request("/keys")).data.keys.length, 0);
  const imported = await client.request("/keys/import", {
    privateKey: encrypted,
    passphrase,
  });
  assert.equal(imported.status, 201, imported.data.error);
  assert.equal(imported.data.key.readyToDecrypt, true);
  assert.equal(imported.data.key.privateKey, undefined);
  const exported = await client.request(
    `/keys/${imported.data.key.id}/export?type=private`,
  );
  assert.equal(
    (
      await openpgp.readPrivateKey({ armoredKey: exported.data.armoredKey })
    ).isDecrypted(),
    true,
  );
  const reopened = await workspace(t, client.dataDirectory);
  const cipher = await reopened.request("/encrypt", {
    keyId: imported.data.key.id,
    message,
  });
  const clear = await reopened.request("/decrypt", {
    keyId: imported.data.key.id,
    message: cipher.data.message,
  });
  assert.equal(clear.data.message, message);
  assert.ok(
    !(
      await readFile(path.join(client.dataDirectory, "keys.json"), "utf8")
    ).includes(passphrase),
  );
});

test("validates optional fingerprints and unlocks an existing key from its details", async (t) => {
  const client = await workspace(t);
  const fingerprint = (
    await openpgp.readKey({ armoredKey: fixture.publicKey })
  ).getFingerprint();
  const mismatch = await client.request("/keys/import", {
    privateKey: fixture.privateKey,
    fingerprint: "0".repeat(40),
  });
  assert.equal(mismatch.status, 400);
  assert.equal((await client.request("/keys")).data.keys.length, 0);
  const imported = await client.request("/keys/import", {
    privateKey: fixture.privateKey,
    fingerprint: fingerprint
      .toUpperCase()
      .match(/.{1,4}/g)
      .join(" "),
  });
  assert.equal(imported.status, 201, imported.data.error);
  assert.equal(imported.data.key.fingerprint, fingerprint.toUpperCase());
  const file = path.join(client.dataDirectory, "keys.json");
  const records = JSON.parse(await readFile(file, "utf8"));
  records[0].privateKey = (
    await openpgp.encryptKey({
      privateKey: await openpgp.readPrivateKey({
        armoredKey: fixture.privateKey,
      }),
      passphrase,
    })
  ).armor();
  records[0].protected = true;
  await writeFile(file, JSON.stringify(records));
  const reopened = await workspace(t, client.dataDirectory);
  const wrongFingerprint = await reopened.request(
    `/keys/${fingerprint}`,
    { fingerprint: "0".repeat(40), passphrase },
    "PATCH",
  );
  assert.equal(wrongFingerprint.status, 400);
  const wrongPassphrase = await reopened.request(
    `/keys/${fingerprint}`,
    { fingerprint, passphrase: "wrong" },
    "PATCH",
  );
  assert.equal(wrongPassphrase.status, 400);
  assert.equal(
    (await reopened.request("/keys")).data.keys[0].readyToDecrypt,
    false,
  );
  const updated = await reopened.request(
    `/keys/${fingerprint}`,
    { fingerprint, passphrase },
    "PATCH",
  );
  assert.equal(updated.status, 200, updated.data.error);
  assert.equal(updated.data.key.readyToDecrypt, true);
  assert.equal(updated.data.key.privateKey, undefined);
  const cipher = await reopened.request("/encrypt", {
    keyId: fingerprint,
    message,
  });
  const clear = await reopened.request("/decrypt", {
    keyId: fingerprint,
    message: cipher.data.message,
  });
  assert.equal(clear.data.message, message);
  assert.ok(!(await readFile(file, "utf8")).includes(passphrase));
});

test("migrates saved unlocked copies and replaces legacy encrypted keys by reimport", async (t) => {
  const client = await workspace(t);
  const key = await importKey(client);
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: fixture.privateKey,
  });
  const encrypted = (
    await openpgp.encryptKey({ privateKey, passphrase })
  ).armor();
  const file = path.join(client.dataDirectory, "keys.json");
  const records = JSON.parse(await readFile(file, "utf8"));
  records[0].privateKey = encrypted;
  records[0].protected = true;
  records[0].decryptionKey = fixture.privateKey;
  await writeFile(file, JSON.stringify(records));
  const migrated = await workspace(t, client.dataDirectory);
  const exported = await migrated.request(
    `/keys/${key.id}/export?type=private`,
  );
  assert.equal(
    (
      await openpgp.readPrivateKey({ armoredKey: exported.data.armoredKey })
    ).isDecrypted(),
    true,
  );
  assert.equal(
    JSON.parse(await readFile(file, "utf8"))[0].decryptionKey,
    undefined,
  );
  records[0].decryptionKey = undefined;
  await writeFile(file, JSON.stringify(records));
  const legacy = await workspace(t, client.dataDirectory);
  assert.equal(
    (await legacy.request("/keys")).data.keys[0].readyToDecrypt,
    false,
  );
  const replaced = await importKey(legacy);
  assert.equal(replaced.id, key.id);
  assert.equal(replaced.readyToDecrypt, true);
  const ciphertext = await legacy.request("/encrypt", {
    keyId: key.id,
    message,
  });
  const clear = await legacy.request("/decrypt", {
    keyId: key.id,
    message: ciphertext.data.message,
  });
  assert.equal(clear.data.message, message);
});

test("encrypts and decrypts text without passwords and does not save messages", async (t) => {
  const client = await workspace(t);
  const key = await importKey(client);
  const encrypted = await client.request("/encrypt", {
    keyId: key.id,
    message,
  });
  assert.equal(encrypted.status, 200, encrypted.data.error);
  assert.match(encrypted.data.message, /BEGIN PGP MESSAGE/);
  const decrypted = await client.request("/decrypt", {
    keyId: key.id,
    message: encrypted.data.message,
  });
  assert.equal(decrypted.status, 200, decrypted.data.error);
  assert.equal(decrypted.data.message, message);
  assert.deepEqual(decrypted.data.signatures, []);
  const saved = await readFile(
    path.join(client.dataDirectory, "keys.json"),
    "utf8",
  );
  assert.ok(!saved.includes(message));
  assert.ok(!saved.includes("BEGIN PGP MESSAGE"));
});

test("public imports can be upgraded to private keys without duplicates or private-key loss", async (t) => {
  const client = await workspace(t);
  const first = await importKey(client, fixture.publicKey);
  assert.equal(first.hasPrivate, false);
  assert.equal(first.privateKey, undefined);
  const upgraded = await importKey(client);
  assert.equal(upgraded.id, first.id);
  assert.equal(upgraded.hasPrivate, true);
  const repeat = await importKey(client, fixture.publicKey);
  assert.equal(repeat.hasPrivate, true);
  assert.equal(repeat.readyToDecrypt, true);
  const list = await client.request("/keys");
  assert.equal(list.data.keys.length, 1);
  assert.equal(list.data.keys[0].publicKey, undefined);
  const exported = await client.request(
    `/keys/${first.id}/export?type=private`,
  );
  assert.match(exported.data.armoredKey, /BEGIN PGP PRIVATE KEY BLOCK/);
});

test("saved keys survive reopening the app; deleted keys stay deleted", async (t) => {
  const original = await workspace(t);
  const key = await importKey(original);
  const reopened = await workspace(t, original.dataDirectory);
  assert.equal((await reopened.request("/keys")).data.keys[0].id, key.id);
  assert.equal(
    (await reopened.request(`/keys/${key.id}`, undefined, "DELETE")).status,
    204,
  );
  const again = await workspace(t, original.dataDirectory);
  assert.equal((await again.request("/keys")).data.keys.length, 0);
});

test("concurrent imports persist both records with no lost updates", async (t) => {
  const client = await workspace(t);
  await Promise.all([importKey(client), importKey(client, second.publicKey)]);
  assert.equal((await client.request("/keys")).data.keys.length, 2);
  assert.equal(
    JSON.parse(
      await readFile(path.join(client.dataDirectory, "keys.json"), "utf8"),
    ).length,
    2,
  );
});

test("validates malformed keys, unavailable recipients, and message armor", async (t) => {
  const client = await workspace(t);
  assert.equal(
    (await client.request("/keys/import", { armoredKey: "garbage" })).status,
    400,
  );
  assert.equal(
    (
      await client.request("/keys/import", {
        armoredKey: fixture.publicKey + second.publicKey,
      })
    ).status,
    400,
  );
  assert.equal(
    (
      await client.request("/keys/generate", {
        name: "Test",
        email: "bad",
      })
    ).status,
    400,
  );
  const key = await importKey(client, fixture.publicKey);
  assert.equal(
    (await client.request("/decrypt", { keyId: key.id, message: "bad" }))
      .status,
    400,
  );
  assert.equal(
    (await client.request("/encrypt", { keyId: "missing", message })).status,
    404,
  );
  assert.equal(
    (await client.request("/encrypt", { keyId: key.id, message: "" })).status,
    400,
  );
  await importKey(client);
  assert.equal(
    (
      await client.request("/decrypt", {
        keyId: key.id,
        message: "bad",
      })
    ).status,
    400,
  );
});

test("blocks cross-origin and DNS-rebinding requests; API results are never cached", async (t) => {
  const client = await workspace(t);
  assert.equal(
    (
      await client.request("/keys", undefined, "GET", {
        Origin: "https://example.com",
      })
    ).status,
    403,
  );
  const rejectedHost = await new Promise((resolve, reject) => {
    http
      .get(
        `${client.base}/api/keys`,
        { headers: { Host: "example.com" } },
        (response) => {
          response.resume();
          resolve(response.statusCode);
        },
      )
      .on("error", reject);
  });
  assert.equal(rejectedHost, 403);
  assert.equal(
    (
      await client.request(
        "/keys/import",
        { armoredKey: fixture.publicKey },
        "POST",
        { "Content-Type": "text/plain" },
      )
    ).status,
    415,
  );
  const response = await client.request("/keys");
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("verifies known signatures and flags unknown signatures", async (t) => {
  const client = await workspace(t);
  const key = await importKey(client);
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: message }),
    encryptionKeys: await openpgp.readKey({ armoredKey: fixture.publicKey }),
    signingKeys: await openpgp.readPrivateKey({
      armoredKey: second.privateKey,
    }),
  });
  const unknown = await client.request("/decrypt", {
    keyId: key.id,
    message: encrypted,
  });
  assert.equal(unknown.status, 200, unknown.data.error);
  assert.equal(unknown.data.signatures[0].verified, false);
  await importKey(client, second.publicKey);
  const known = await client.request("/decrypt", {
    keyId: key.id,
    message: encrypted,
  });
  assert.equal(known.data.signatures[0].verified, true);
});

test("corrupt vault files fail safely instead of being overwritten", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "cipher-corrupt-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(path.join(directory, "keys.json"), "not valid json");
  await assert.rejects(createApp({ dataDirectory: directory }));
  assert.equal(
    await readFile(path.join(directory, "keys.json"), "utf8"),
    "not valid json",
  );
});

test(
  "interoperates with GnuPG in both directions",
  { skip: spawnSync("gpg", ["--version"]).status !== 0 },
  async (t) => {
    const client = await workspace(t);
    const key = await importKey(client);
    const home = await mkdtemp(path.join(os.tmpdir(), "cipher-gpg-"));
    t.after(() => rm(home, { recursive: true, force: true }));
    const gpg = (args, input) => {
      const result = spawnSync(
        "gpg",
        ["--homedir", home, "--batch", "--yes", ...args],
        { input, encoding: "utf8" },
      );
      assert.equal(result.status, 0, result.stderr);
      return result.stdout;
    };
    gpg(["--import"], fixture.privateKey);
    const ciphertext = (
      await client.request("/encrypt", { keyId: key.id, message })
    ).data.message;
    const encryptedFile = path.join(home, "cipher.asc");
    await writeFile(encryptedFile, ciphertext);
    const clear = gpg(["--decrypt", encryptedFile]);
    assert.equal(clear.replace(/\r\n/g, "\n"), message);
    const gpgEncrypted = gpg(
      [
        "--trust-model",
        "always",
        "--recipient",
        key.id,
        "--armor",
        "--encrypt",
      ],
      message,
    );
    const decrypted = await client.request("/decrypt", {
      keyId: key.id,
      message: gpgEncrypted,
    });
    assert.equal(decrypted.status, 200, decrypted.data.error);
    assert.equal(decrypted.data.message, message);
  },
);
