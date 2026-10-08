import express from "express";
import * as openpgp from "openpgp";
import { createStore } from "./store.js";

class UserError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const publicRecord = ({
  publicKey,
  privateKey,
  decryptionKey,
  fingerprint,
  protected: encrypted,
  revocationCertificate,
  ...record
}) => ({
  ...record,
  fingerprint: record.id.toUpperCase(),
  readyToDecrypt: Boolean(privateKey && !encrypted),
});
const requireText = (value, label, max = 500_000) => {
  if (typeof value !== "string" || !value.trim())
    throw new UserError(`${label} is required.`);
  if (value.length > max)
    throw new UserError(
      `${label} is too long (maximum ${max.toLocaleString()} characters).`,
    );
  return value;
};

function checkFingerprint(value, actual) {
  if (value == null || value === "") return;
  if (typeof value !== "string" || value.length > 200)
    throw new UserError("Enter the full key fingerprint.");
  const normalized = value.replace(/[\s:]/g, "").toLowerCase();
  if (!normalized) return;
  if (normalized !== actual.toLowerCase())
    throw new UserError(
      "That fingerprint does not match this key. Check the full fingerprint and try again.",
    );
}

async function unlockPrivateKey(key, passphrase) {
  if (key.isDecrypted()) return key;
  passphrase ??= "";
  if (typeof passphrase !== "string" || passphrase.length > 1024)
    throw new UserError("Use a key passphrase under 1,024 characters.");
  try {
    return await openpgp.decryptKey({ privateKey: key, passphrase });
  } catch {
    const error = new UserError(
      passphrase
        ? "That passphrase did not unlock the key. Try again."
        : "This private key has existing passphrase protection. Enter its passphrase once to finish importing it.",
    );
    error.code = "KEY_PASSPHRASE_REQUIRED";
    throw error;
  }
}

async function describe(key, label) {
  const identity = key.users.find((user) => user.userID)?.userID;
  const expiration = await key.getExpirationTime().catch(() => null);
  let canEncrypt = true;
  try {
    await key.getEncryptionKey();
  } catch {
    canEncrypt = false;
  }
  return {
    id: key.getFingerprint(),
    name: label?.trim() || identity?.name || identity?.email || "Unnamed key",
    email: identity?.email || "",
    userIds: key.getUserIDs(),
    hasPrivate: key.isPrivate(),
    protected: key.isPrivate() && !key.isDecrypted(),
    algorithm: key.getAlgorithmInfo().curve || key.getAlgorithmInfo().algorithm,
    created: key.getCreationTime().toISOString(),
    expires: expiration instanceof Date ? expiration.toISOString() : null,
    canEncrypt,
    publicKey: key.toPublic().armor(),
    privateKey: key.isPrivate() ? key.armor() : null,
  };
}

export async function createApp({ dataDirectory }) {
  const app = express();
  const store = await createStore(dataDirectory);
  if (store.all().some((record) => record.decryptionKey)) {
    await store.mutate(async (keys) => {
      for (const record of keys) {
        if (!record.decryptionKey) continue;
        const key = await openpgp.readPrivateKey({
          armoredKey: record.decryptionKey,
        });
        if (!key.isDecrypted() || key.getFingerprint() !== record.id)
          throw new Error("The saved decryption key is invalid.");
        record.privateKey = key.armor();
        record.protected = false;
        delete record.decryptionKey;
      }
    });
  }
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    const host = req.headers.host || "";
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host))
      return res
        .status(403)
        .json({ error: "This workspace is only available on localhost." });
    if (
      (req.headers.origin && req.headers.origin !== `http://${host}`) ||
      req.headers["sec-fetch-site"] === "cross-site"
    ) {
      return res
        .status(403)
        .json({ error: "Cross-origin access to the local vault is blocked." });
    }
    res.set({
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
    });
    if (req.path.startsWith("/api/")) {
      res.set("Cache-Control", "no-store");
      if (
        !["GET", "HEAD"].includes(req.method) &&
        !/^application\/json(?:\s*;|$)/i.test(req.headers["content-type"] || "")
      ) {
        return res
          .status(415)
          .json({ error: "Use an application/json request." });
      }
    }
    next();
  });
  app.use(express.json({ limit: "2mb" }));
  app.use("/api", (req, res, next) => {
    if (
      req.body != null &&
      (typeof req.body !== "object" || Array.isArray(req.body))
    )
      return res
        .status(400)
        .json({ error: "Use a JSON object for this request." });
    req.body ||= {};
    next();
  });
  app.get("/api/health", (req, res) =>
    res.json({ status: "ok", storage: "local", keys: store.all().length }),
  );
  app.get("/api/keys", (req, res) =>
    res.json({ keys: store.all().map(publicRecord) }),
  );

  async function save(key, label, revocationCertificate) {
    return store.mutate(async (keys) => {
      const id = key.getFingerprint();
      const index = keys.findIndex((item) => item.id === id);
      const existing = keys[index];
      if (existing) {
        const old = await openpgp.readKey({
          armoredKey: existing.privateKey || existing.publicKey,
        });
        key = key.isPrivate() ? await key.update(old) : await old.update(key);
      }
      const record = {
        ...(await describe(key, label || existing?.name)),
        added: existing?.added || new Date().toISOString(),
        revocationCertificate:
          revocationCertificate || existing?.revocationCertificate || null,
        hasRevocation: Boolean(
          revocationCertificate || existing?.revocationCertificate,
        ),
      };
      if (index < 0) keys.push(record);
      else keys[index] = record;
      return publicRecord(record);
    });
  }

  app.post("/api/keys/import", async (req, res) => {
    if (
      req.body.label != null &&
      (typeof req.body.label !== "string" || req.body.label.length > 100)
    )
      throw new UserError("Use a key label under 100 characters.");
    async function readImport(value, label, expectedPrivate) {
      const armor = requireText(value, label);
      if (
        (armor.match(/-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----/g) || [])
          .length !== 1
      ) {
        throw new UserError(
          `Include one complete armored PGP key in the ${label.toLowerCase()} field.`,
        );
      }
      let parsed;
      try {
        parsed = await openpgp.readKey({ armoredKey: armor });
      } catch {
        throw new UserError(
          `${label} could not be read. Include the complete BEGIN and END PGP KEY BLOCK lines.`,
        );
      }
      if (
        expectedPrivate !== undefined &&
        parsed.isPrivate() !== expectedPrivate
      ) {
        throw new UserError(
          `The ${label.toLowerCase()} field contains a ${parsed.isPrivate() ? "private" : "public"} key. Move it to the matching field.`,
        );
      }
      return parsed;
    }
    let key;
    if (req.body.publicKey !== undefined || req.body.privateKey !== undefined) {
      for (const field of ["publicKey", "privateKey"]) {
        if (req.body[field] != null && typeof req.body[field] !== "string")
          throw new UserError("Keys must be armored PGP text.");
      }
      const publicKey = req.body.publicKey?.trim()
        ? await readImport(req.body.publicKey, "Public key", false)
        : null;
      const privateKey = req.body.privateKey?.trim()
        ? await readImport(req.body.privateKey, "Private key", true)
        : null;
      if (!publicKey && !privateKey)
        throw new UserError("Add a public key, a private key, or both.");
      if (
        publicKey &&
        privateKey &&
        publicKey.getFingerprint() !== privateKey.getFingerprint()
      ) {
        throw new UserError(
          "These public and private keys do not match. Import them separately or choose a matching key pair.",
        );
      }
      key =
        privateKey && publicKey
          ? await privateKey.update(publicKey)
          : privateKey || publicKey;
    } else {
      key = await readImport(req.body.armoredKey, "PGP key");
    }
    checkFingerprint(req.body.fingerprint, key.getFingerprint());
    if (key.isPrivate()) key = await unlockPrivateKey(key, req.body.passphrase);
    res.status(201).json({ key: await save(key, req.body.label) });
  });
  app.post("/api/keys/generate", async (req, res) => {
    const name = requireText(req.body.name, "Name", 100).trim();
    const email = requireText(req.body.email, "Email", 254).trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      throw new UserError("Enter a valid email address.");
    const { privateKey, revocationCertificate } = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519",
      userIDs: [{ name, email }],
      format: "armored",
    });
    const generated = await openpgp.readPrivateKey({ armoredKey: privateKey });
    res.status(201).json({
      key: await save(generated, name, revocationCertificate),
    });
  });

  const findKey = (id) => {
    const key = store.get(id);
    if (!key)
      throw new UserError(
        "This key is no longer in your vault. Choose another key.",
        404,
      );
    return key;
  };
  app.patch("/api/keys/:id", async (req, res) => {
    const saved = findKey(req.params.id);
    checkFingerprint(req.body.fingerprint, saved.id);
    const updated = await store.mutate(async (keys) => {
      const record = keys.find((item) => item.id === saved.id);
      if (!record) throw new UserError("Key not found.", 404);
      if (record.privateKey) {
        const key = await unlockPrivateKey(
          await openpgp.readPrivateKey({ armoredKey: record.privateKey }),
          req.body.passphrase,
        );
        record.privateKey = key.armor();
        record.protected = false;
      }
      return publicRecord(record);
    });
    res.json({ key: updated });
  });
  app.get("/api/keys/:id/export", (req, res) => {
    const key = findKey(req.params.id);
    const type = req.query.type || "public";
    if (!["public", "private", "revocation"].includes(type))
      throw new UserError("Choose public, private, or revocation export.");
    const armoredKey =
      type === "private"
        ? key.privateKey
        : type === "revocation"
          ? key.revocationCertificate
          : key.publicKey;
    if (!armoredKey)
      throw new UserError(
        `This key has no ${type} key material to export.`,
        404,
      );
    res.json({
      armoredKey,
      filename: `${key.name.replace(/[^a-zA-Z0-9_-]/g, "-").slice(0, 60)}-${type}.asc`,
    });
  });
  app.delete("/api/keys/:id", async (req, res) => {
    await store.mutate((keys) => {
      const index = keys.findIndex((key) => key.id === req.params.id);
      if (index === -1) throw new UserError("Key not found.", 404);
      keys.splice(index, 1);
    });
    res.status(204).end();
  });
  app.post("/api/encrypt", async (req, res) => {
    const text = requireText(req.body.message, "Message");
    const recipient = findKey(req.body.keyId);
    try {
      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text }),
        encryptionKeys: await openpgp.readKey({
          armoredKey: recipient.publicKey,
        }),
        format: "armored",
      });
      res.json({ message: encrypted });
    } catch {
      throw new UserError(
        "This key cannot encrypt messages. It may be expired, revoked, or missing an encryption subkey.",
      );
    }
  });
  app.post("/api/decrypt", async (req, res) => {
    const text = requireText(req.body.message, "Encrypted message");
    const saved = findKey(req.body.keyId);
    if (!saved.privateKey)
      throw new UserError(
        "Decryption requires a private key. Import your private key first.",
      );
    const key = await openpgp.readPrivateKey({
      armoredKey: saved.privateKey,
    });
    if (!key.isDecrypted())
      throw new UserError(
        "Import this private key once to unlock it for decryption.",
      );
    let message;
    try {
      message = await openpgp.readMessage({ armoredMessage: text });
    } catch {
      throw new UserError(
        "Paste a complete encrypted PGP message, including the BEGIN and END PGP MESSAGE lines.",
      );
    }
    let result;
    try {
      result = await openpgp.decrypt({
        message,
        decryptionKeys: key,
        format: "utf8",
        verificationKeys: await Promise.all(
          store
            .all()
            .map((item) => openpgp.readKey({ armoredKey: item.publicKey })),
        ),
        config: { maxDecompressedMessageSize: 2_000_000 },
      });
    } catch {
      throw new UserError(
        "Unable to decrypt this message. Check that this private key belongs to a recipient and the message is complete.",
      );
    }
    const signatures = await Promise.all(
      result.signatures.map(async (signature) => {
        let verified = false;
        try {
          await signature.verified;
          verified = true;
        } catch {
          /* Unknown or invalid signer. */
        }
        return { keyId: signature.keyID.toHex(), verified };
      }),
    );
    res.json({ message: result.data, signatures });
  });
  app.use("/api", (req, res) =>
    res.status(404).json({ error: "API endpoint not found." }),
  );
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status = error.status || 500;
    // Never log request bodies, keys, passphrases, or plaintext.
    if (status >= 500) console.error("A local workspace operation failed.");
    const message =
      error instanceof UserError
        ? error.message
        : status === 413
          ? "This file or message is too large."
          : status === 400
            ? "The request could not be read."
            : "The local operation failed. Check that the vault folder is writable.";
    res.status(status).json({
      error: message,
      ...(error.code === "KEY_PASSPHRASE_REQUIRED" ? { code: error.code } : {}),
    });
  });
  return app;
}
