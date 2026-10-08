import { useEffect, useRef, useState } from "react";
import KeySelect from "./KeySelect.jsx";
import {
  ArrowDownToLine,
  Check,
  CircleHelp,
  Copy,
  FileKey2,
  HardDrive,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Plus,
  Search,
  ShieldCheck,
  Sparkles,
  Trash2,
  UnlockKeyhole,
  Upload,
  X,
} from "lucide-react";

async function api(url, options = {}) {
  const response = await fetch(`/api${url}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  if (response.status === 204) return null;
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(
      data.error || "The local server could not complete the request.",
    );
    error.code = data.code;
    throw error;
  }
  return data;
}
function download(text, filename) {
  const url = URL.createObjectURL(
    new Blob([text], { type: "text/plain;charset=utf-8" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const date = (value) =>
  new Date(value).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });

function Modal({
  title,
  description,
  children,
  onClose,
  busy = false,
  wide = false,
}) {
  const ref = useRef(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={`modal ${wide ? "modal-wide" : ""}`}
      aria-labelledby="modal-title"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
      onClick={(event) => {
        if (event.target === ref.current && !busy) onClose();
      }}
    >
      <div className="modal-content">
        <div className="modal-heading">
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
            disabled={busy}
          >
            <X size={20} />
          </button>
        </div>
        <h2 id="modal-title">{title}</h2>
        <p className="modal-description">{description}</p>
        {children}
      </div>
    </dialog>
  );
}

function AddKeyModal({ initialMode, onClose, onSaved }) {
  const [mode, setMode] = useState(initialMode);
  const [armors, setArmors] = useState({ public: "", private: "" });
  const [label, setLabel] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [needsPassphrase, setNeedsPassphrase] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const keyFileInputs = useRef({});
  async function readFile(event, kind) {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 1_000_000) {
      setError("Choose a key file smaller than 1 MB.");
      return;
    }
    try {
      const armor = await file.text();
      setArmors((previous) => ({ ...previous, [kind]: armor }));
      setNeedsPassphrase(false);
      setPassphrase("");
      setError("");
    } catch {
      setError("This file could not be read. Try pasting the key instead.");
    }
    event.target.value = "";
  }
  async function submit(event) {
    event.preventDefault();
    setError("");
    if (mode === "import" && !armors.public.trim() && !armors.private.trim()) {
      setError("Add a public key, a private key, or both.");
      return;
    }
    setBusy(true);
    try {
      const data = await api(`/keys/${mode}`, {
        method: "POST",
        body: JSON.stringify(
          mode === "import"
            ? {
                publicKey: armors.public,
                privateKey: armors.private,
                label,
                passphrase,
                fingerprint,
              }
            : { name, email },
        ),
      });
      setArmors({ public: "", private: "" });
      setPassphrase("");
      onSaved(data.key);
    } catch (error) {
      if (error.code === "KEY_PASSPHRASE_REQUIRED") setNeedsPassphrase(true);
      setError(error.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title="Add key"
      description="Import a PGP key or generate a new key pair."
      onClose={onClose}
      busy={busy}
    >
      <div className="modal-tabs">
        <button
          type="button"
          disabled={busy}
          className={mode === "import" ? "active" : ""}
          onClick={() => {
            setMode("import");
            setError("");
          }}
        >
          <Upload size={16} />
          Import key
        </button>
        <button
          type="button"
          disabled={busy}
          className={mode === "generate" ? "active" : ""}
          onClick={() => {
            setMode("generate");
            setError("");
          }}
        >
          <Sparkles size={16} />
          Generate key pair
        </button>
      </div>
      <form onSubmit={submit}>
        {mode === "import" ? (
          <>
            <label className="field-label" htmlFor="key-label">
              Key label <span>optional</span>
            </label>
            <input
              id="key-label"
              placeholder="e.g. My key pair"
              value={label}
              maxLength={100}
              onChange={(e) => setLabel(e.target.value)}
              disabled={busy}
            />
            <p className="field-note">
              Import either key, or both for a matching key pair.
            </p>
            {["public", "private"].map((kind) => (
              <div key={kind}>
                <div className="field-label-row">
                  <label className="field-label" htmlFor={`key-${kind}`}>
                    {kind === "public" ? "Public key" : "Private key"}{" "}
                    <span>optional</span>
                  </label>
                  <button
                    type="button"
                    className="button secondary button-small"
                    aria-label={`Choose ${kind} key file`}
                    onClick={() => keyFileInputs.current[kind].click()}
                    disabled={busy}
                  >
                    <Upload size={14} />
                    Choose file
                  </button>
                </div>
                <input
                  ref={(element) => {
                    keyFileInputs.current[kind] = element;
                  }}
                  type="file"
                  accept=".asc,.pgp,.txt,.key"
                  onChange={(event) => readFile(event, kind)}
                  hidden
                />
                <textarea
                  id={`key-${kind}`}
                  className="armor-input import-key-input"
                  placeholder={`-----BEGIN PGP ${kind.toUpperCase()} KEY BLOCK-----\n\nPaste your ${kind} key here.\n\n-----END PGP ${kind.toUpperCase()} KEY BLOCK-----`}
                  value={armors[kind]}
                  onChange={(event) => {
                    setArmors((previous) => ({
                      ...previous,
                      [kind]: event.target.value,
                    }));
                    setError("");
                    setNeedsPassphrase(false);
                    setPassphrase("");
                  }}
                  disabled={busy}
                  spellCheck={false}
                  maxLength={500000}
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                />
              </div>
            ))}
            <label className="field-label" htmlFor="import-key-passphrase">
              Passphrase <span>optional</span>
            </label>
            <input
              id="import-key-passphrase"
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              placeholder="If your private key has a passphrase"
              autoComplete="off"
              maxLength={1024}
              disabled={busy}
              required={needsPassphrase}
            />
            <label className="field-label" htmlFor="import-key-fingerprint">
              Fingerprint <span>optional</span>
            </label>
            <input
              id="import-key-fingerprint"
              value={fingerprint}
              onChange={(event) => setFingerprint(event.target.value)}
              placeholder="Paste the full fingerprint to verify this key"
              autoComplete="off"
              spellCheck={false}
              maxLength={200}
              disabled={busy}
            />
            <p className="field-note">
              The passphrase unlocks the key once and isn’t saved. A fingerprint
              is checked against the imported key.
            </p>
            <p className="field-note">
              <HardDrive size={14} />
              Import your PGP key as-is. Keys are saved locally.
            </p>
          </>
        ) : (
          <>
            <div className="two-fields">
              <div>
                <label className="field-label" htmlFor="key-name">
                  Your name
                </label>
                <input
                  id="key-name"
                  placeholder="Alex Morgan"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  maxLength={100}
                  disabled={busy}
                />
              </div>
              <div>
                <label className="field-label" htmlFor="key-email">
                  Email address
                </label>
                <input
                  id="key-email"
                  type="email"
                  placeholder="alex@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  maxLength={254}
                  disabled={busy}
                />
              </div>
            </div>
            <div className="gentle-note">
              <ShieldCheck size={20} />
              <p>
                Creates a key pair and saves it locally, ready to encrypt and
                decrypt messages.
              </p>
            </div>
          </>
        )}
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-footer">
          <button
            type="button"
            className="button secondary"
            disabled={busy}
            onClick={onClose}
          >
            Cancel
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? (
              <LoaderCircle className="spin" size={17} />
            ) : mode === "import" ? (
              <Upload size={17} />
            ) : (
              <Sparkles size={17} />
            )}
            {busy
              ? "Working…"
              : mode === "import"
                ? "Save key locally"
                : "Create key pair"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function KeyInfoForm({ keyRecord, onSaved }) {
  const [fingerprint, setFingerprint] = useState(
    keyRecord.fingerprint || keyRecord.id.toUpperCase(),
  );
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setSaved(false);
    try {
      const data = await api(`/keys/${keyRecord.id}`, {
        method: "PATCH",
        body: JSON.stringify({ fingerprint, passphrase }),
      });
      setPassphrase("");
      onSaved(data.key);
      setSaved(true);
    } catch (error) {
      setError(error.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit} className="key-info-form">
      <label className="field-label" htmlFor="saved-key-fingerprint">
        Fingerprint <span>optional</span>
      </label>
      <input
        id="saved-key-fingerprint"
        value={fingerprint}
        onChange={(event) => {
          setFingerprint(event.target.value);
          setSaved(false);
        }}
        maxLength={200}
        spellCheck={false}
        disabled={busy}
      />
      {keyRecord.hasPrivate && (
        <>
          <label className="field-label" htmlFor="saved-key-passphrase">
            Passphrase <span>optional</span>
          </label>
          <input
            id="saved-key-passphrase"
            type="password"
            value={passphrase}
            onChange={(event) => {
              setPassphrase(event.target.value);
              setSaved(false);
            }}
            placeholder="If this private key still needs unlocking"
            autoComplete="off"
            maxLength={1024}
            disabled={busy}
          />
        </>
      )}
      <p className="field-note">
        The fingerprint verifies this key. A passphrase is only used to unlock a
        protected key once; it isn’t saved.
      </p>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      {saved && (
        <p className="field-note" role="status">
          Key information verified and saved.
        </p>
      )}
      <button className="button secondary" disabled={busy}>
        {busy ? "Saving…" : "Save key info"}
      </button>
    </form>
  );
}

function App() {
  const [page, setPage] = useState("messages");
  const [mode, setMode] = useState("encrypt");
  const [keys, setKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [connectionError, setConnectionError] = useState("");
  const [drafts, setDrafts] = useState({
    encrypt: { input: "", keyId: "", output: "", signatures: [] },
    decrypt: { input: "", keyId: "", output: "", signatures: [] },
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [modal, setModal] = useState(null);
  const [notice, setNotice] = useState("");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const [deleting, setDeleting] = useState(false);
  const [copyingKeyId, setCopyingKeyId] = useState("");
  const fileInput = useRef(null);
  const draft = drafts[mode];
  const eligible = keys.filter((key) =>
    mode === "encrypt" ? key.canEncrypt : key.hasPrivate,
  );
  const selected = eligible.find((key) => key.id === draft.keyId);
  const encrypting = mode === "encrypt";
  const updateDraft = (update) => {
    setDrafts((previous) => ({
      ...previous,
      [mode]: { ...previous[mode], ...update, output: "", signatures: [] },
    }));
    setError("");
  };

  async function refresh() {
    try {
      const data = await api("/keys");
      setKeys(data.keys);
      setConnectionError("");
    } catch (error) {
      setConnectionError(error.message);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    refresh();
  }, []);
  useEffect(() => {
    setDrafts((previous) => {
      const next = { ...previous };
      for (const kind of ["encrypt", "decrypt"]) {
        const available = keys.filter((key) =>
          kind === "encrypt" ? key.canEncrypt : key.hasPrivate,
        );
        if (!available.some((key) => key.id === previous[kind].keyId))
          next[kind] = {
            ...previous[kind],
            keyId: available[0]?.id || "",
            output: "",
            signatures: [],
          };
      }
      return next;
    });
  }, [keys]);
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(""), 4500);
    return () => clearTimeout(timer);
  }, [notice]);

  async function copy(value, success = "Copied to clipboard") {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(success);
    } catch {
      setError(
        "Clipboard access is unavailable. Select the text and copy it manually.",
      );
    }
  }
  async function transform() {
    if (busy || !draft.input.trim() || !selected) return;
    setBusy(true);
    setError("");
    try {
      const data = await api(`/${mode}`, {
        method: "POST",
        body: JSON.stringify({
          message: draft.input,
          keyId: selected.id,
        }),
      });
      setDrafts((previous) => ({
        ...previous,
        [mode]: {
          ...previous[mode],
          output: data.message,
          signatures: data.signatures || [],
        },
      }));
      setNotice(encrypting ? "Message encrypted" : "Message decrypted");
    } catch (error) {
      setError(error.message);
    } finally {
      setBusy(false);
    }
  }
  async function readMessage(event) {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 500_000) {
      setError("Choose a message file smaller than 500 KB.");
      return;
    }
    try {
      updateDraft({ input: await file.text() });
    } catch {
      setError("This file could not be read.");
    }
    event.target.value = "";
  }
  async function exportKey(key, type) {
    try {
      const data = await api(`/keys/${key.id}/export?type=${type}`);
      download(data.armoredKey, data.filename);
      setNotice(
        `${type === "revocation" ? "Revocation certificate" : `${type[0].toUpperCase()}${type.slice(1)} key`} exported`,
      );
    } catch (error) {
      setError(error.message);
    }
  }
  async function copyPublicKey(key) {
    setCopyingKeyId(key.id);
    setError("");
    try {
      const data = await api(`/keys/${key.id}/export?type=public`);
      await copy(data.armoredKey, "Public key copied to clipboard");
    } catch (error) {
      setError(error.message);
    } finally {
      setCopyingKeyId("");
    }
  }
  async function deleteKey(key) {
    setDeleting(true);
    try {
      await api(`/keys/${key.id}`, { method: "DELETE" });
      await refresh();
      setModal(null);
      setNotice("Key removed from this device");
    } catch (error) {
      setError(error.message);
    } finally {
      setDeleting(false);
    }
  }
  function switchMode(next) {
    setMode(next);
    setError("");
  }
  function navigate(next) {
    setPage(next);
    setError("");
  }
  const filtered = keys.filter(
    (key) =>
      (filter !== "private" || key.hasPrivate) &&
      (filter !== "public" || !key.hasPrivate) &&
      `${key.name} ${key.email}`
        .toLowerCase()
        .includes(search.toLowerCase().trim()),
  );

  return (
    <div className="app-shell">
      <header className="app-header">
        <button
          className="brand"
          onClick={() => navigate("messages")}
          aria-label="PGP Manager home"
        >
          <img src="/favicon.svg?v=key2" width="28" height="28" alt="" />
          PGP Manager
        </button>
        <nav aria-label="Main navigation">
          <button
            className={`nav-item ${page === "messages" ? "active" : ""}`}
            aria-current={page === "messages" ? "page" : undefined}
            onClick={() => navigate("messages")}
          >
            Messages
          </button>
          <button
            className={`nav-item ${page === "keys" ? "active" : ""}`}
            aria-current={page === "keys" ? "page" : undefined}
            onClick={() => navigate("keys")}
          >
            Keys <span className="nav-count">{keys.length}</span>
          </button>
        </nav>
        <div className="header-tools">
          <span className="local-status">
            <span
              className={`status-dot ${connectionError ? "offline" : ""}`}
            />
            {connectionError
              ? "Disconnected"
              : loading
                ? "Connecting…"
                : "Local storage"}
          </span>
          <button
            className="button secondary button-small"
            onClick={() => setModal({ type: "help" })}
          >
            <CircleHelp size={17} />
            Help
          </button>
        </div>
      </header>
      <main className="page-content">
        <div className="page-heading">
          <h1>{page === "messages" ? "Messages" : "Keys"}</h1>
          {page === "messages" && (
            <div
              className="mode-tabs"
              role="tablist"
              aria-label="Message operation"
            >
              <button
                role="tab"
                aria-selected={encrypting}
                className={encrypting ? "active" : ""}
                onClick={() => switchMode("encrypt")}
                disabled={busy}
              >
                <LockKeyhole size={16} />
                Encrypt
              </button>
              <button
                role="tab"
                aria-selected={!encrypting}
                className={!encrypting ? "active" : ""}
                onClick={() => switchMode("decrypt")}
                disabled={busy}
              >
                <UnlockKeyhole size={16} />
                Decrypt
              </button>
            </div>
          )}
        </div>
        {connectionError && (
          <div className="connection-error" role="alert">
            <span>{connectionError}</span>
            <button className="button secondary button-small" onClick={refresh}>
              Retry connection
            </button>
          </div>
        )}
        {page === "messages" ? (
          <section
            className="message-workspace"
            aria-label={`${encrypting ? "Encrypt" : "Decrypt"} a message`}
          >
            <div className="key-picker">
              <div className="picker-field">
                <label className="field-label" htmlFor="message-key">
                  {encrypting ? "Recipient’s public key" : "Your private key"}
                </label>
                <KeySelect
                  id="message-key"
                  label={
                    encrypting ? "Recipient’s public key" : "Your private key"
                  }
                  keys={eligible}
                  value={selected?.id || ""}
                  placeholder={
                    loading
                      ? "Loading keys…"
                      : encrypting
                        ? "Select a public key"
                        : "Select a private key"
                  }
                  disabled={!eligible.length || busy || loading}
                  onChange={(keyId) => {
                    updateDraft({ keyId });
                  }}
                />
              </div>
              <button
                className="button secondary"
                onClick={() => setModal({ type: "add", mode: "import" })}
                disabled={busy}
              >
                <Plus size={16} />
                Import key
              </button>
            </div>
            <div className="message-columns">
              <div className="input-panel">
                <div className="panel-header">
                  <h2>{encrypting ? "Message" : "Encrypted message"}</h2>
                  <button
                    className="button secondary button-small"
                    aria-label="Import message from a file"
                    onClick={() => fileInput.current.click()}
                    disabled={busy}
                  >
                    <Upload size={15} />
                    Import file
                  </button>
                </div>
                <input
                  ref={fileInput}
                  type="file"
                  accept=".txt,.asc,.pgp"
                  onChange={readMessage}
                  hidden
                />
                <textarea
                  className={`message-input ${!encrypting ? "monospace" : ""}`}
                  aria-label={
                    encrypting ? "Message to encrypt" : "Message to decrypt"
                  }
                  placeholder={
                    encrypting
                      ? "Enter the message to encrypt."
                      : "-----BEGIN PGP MESSAGE-----\n\nPaste the encrypted message here.\n\n-----END PGP MESSAGE-----"
                  }
                  value={draft.input}
                  onChange={(e) => updateDraft({ input: e.target.value })}
                  onKeyDown={(e) => {
                    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                      e.preventDefault();
                      transform();
                    }
                  }}
                  disabled={busy}
                  maxLength={500000}
                  spellCheck={encrypting}
                />
                <div className="input-panel-footer">
                  <span>{draft.input.length.toLocaleString()} characters</span>
                  <button
                    className="button secondary button-small"
                    onClick={() => {
                      updateDraft({ input: "" });
                    }}
                    disabled={busy || (!draft.input && !draft.output)}
                  >
                    Clear
                  </button>
                </div>
              </div>
              <div className="output-panel">
                <div className="panel-header">
                  <h2>
                    {encrypting ? "Encrypted message" : "Decrypted message"}
                  </h2>
                </div>
                <textarea
                  className={`message-output ${encrypting ? "monospace" : ""}`}
                  aria-label="Message result"
                  value={draft.output}
                  placeholder={
                    encrypting
                      ? "Encrypted output will appear here."
                      : "Decrypted output will appear here."
                  }
                  readOnly
                  spellCheck={false}
                />
                <div className="output-panel-footer">
                  <span className="result-status">
                    {draft.output ? (
                      <>
                        <Check size={14} />
                        {encrypting ? "Encrypted" : "Decrypted"}
                      </>
                    ) : (
                      "No result"
                    )}
                  </span>
                  <div className="result-actions">
                    <button
                      className="button secondary button-small"
                      aria-label="Copy message result"
                      onClick={() => copy(draft.output)}
                      disabled={!draft.output}
                    >
                      <Copy size={15} />
                      Copy
                    </button>
                    <button
                      className="button secondary button-small"
                      aria-label="Download message result"
                      onClick={() =>
                        download(
                          draft.output,
                          encrypting
                            ? "encrypted-message.asc"
                            : "decrypted-message.txt",
                        )
                      }
                      disabled={!draft.output}
                    >
                      <ArrowDownToLine size={15} />
                      Download
                    </button>
                  </div>
                </div>
              </div>
            </div>
            {!encrypting && selected && !selected.readyToDecrypt && (
              <div className="key-replacement-row">
                <span>Import this private key once to enable decryption.</span>
                <button
                  className="button secondary"
                  onClick={() => setModal({ type: "add", mode: "import" })}
                >
                  Import private key
                </button>
              </div>
            )}
            {error && (
              <p className="workspace-error" role="alert">
                {error}
              </p>
            )}
            {draft.output && !encrypting && (
              <div
                className={`signature-note ${draft.signatures.length && draft.signatures.every((signature) => signature.verified) ? "verified" : ""}`}
              >
                <ShieldCheck size={16} />
                {draft.signatures.length
                  ? draft.signatures.every((signature) => signature.verified)
                    ? "Sender signature verified."
                    : "Sender signature could not be verified. Confirm the sender separately."
                  : "Unsigned message. Sender identity is not verified."}
              </div>
            )}
            <div className="action-row">
              <span className="action-hint">
                {!eligible.length
                  ? encrypting
                    ? "Import a public key to encrypt a message."
                    : "Import a private key to decrypt a message."
                  : "Ctrl / ⌘ + Enter"}
              </span>
              <button
                className="button primary"
                onClick={transform}
                disabled={
                  !draft.input.trim() ||
                  !selected ||
                  busy ||
                  (!encrypting && !selected.readyToDecrypt)
                }
              >
                {busy ? (
                  <LoaderCircle size={17} className="spin" />
                ) : encrypting ? (
                  <LockKeyhole size={17} />
                ) : (
                  <UnlockKeyhole size={17} />
                )}
                {busy
                  ? "Working…"
                  : encrypting
                    ? "Encrypt message"
                    : "Decrypt message"}
              </button>
            </div>
          </section>
        ) : (
          <>
            <div className="vault-toolbar">
              <div className="search-box">
                <Search size={17} />
                <input
                  aria-label="Search keys"
                  placeholder="Search name or email"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              <div className="vault-toolbar-actions">
                <button
                  className="button secondary"
                  onClick={() => setModal({ type: "add", mode: "generate" })}
                >
                  <Plus size={16} />
                  Generate key pair
                </button>
                <button
                  className="button primary"
                  onClick={() => setModal({ type: "add", mode: "import" })}
                >
                  <Upload size={16} />
                  Import key
                </button>
              </div>
            </div>
            <div className="vault-filter" aria-label="Filter keys">
              {[
                ["all", "All keys"],
                ["public", "Public only"],
                ["private", "Key pairs"],
              ].map(([value, text]) => (
                <button
                  key={value}
                  className={filter === value ? "active" : ""}
                  onClick={() => setFilter(value)}
                  aria-pressed={filter === value}
                >
                  {text}
                  {value === "all" && <span>{keys.length}</span>}
                </button>
              ))}
            </div>
            {loading ? (
              <div className="vault-empty">
                <LoaderCircle className="spin" size={20} />
                <p>Loading keys…</p>
              </div>
            ) : !keys.length ? (
              <div className="vault-empty">
                <h2>No keys saved</h2>
                <p>Import a PGP key or generate a key pair.</p>
              </div>
            ) : !filtered.length ? (
              <div className="vault-empty">
                <h2>No matching keys</h2>
                <button
                  className="button secondary button-small"
                  onClick={() => {
                    setSearch("");
                    setFilter("all");
                  }}
                >
                  Clear filters
                </button>
              </div>
            ) : (
              <div className="key-grid">
                {filtered.map((key) => (
                  <article className="key-card" key={key.id}>
                    <div className="key-card-top">
                      <div className="key-card-name">
                        <h2>{key.name}</h2>
                        <p>{key.email || "No email"}</p>
                      </div>
                      <span className="key-type">
                        {key.hasPrivate ? "Key pair" : "Public key"}
                      </span>
                    </div>
                    <div className="key-card-info">
                      <span>
                        {!key.canEncrypt
                          ? "Unavailable for encryption"
                          : key.hasPrivate
                            ? key.readyToDecrypt
                              ? "Ready to decrypt"
                              : "Import to enable decryption"
                            : "Ready to encrypt"}
                      </span>
                      <span>Added {date(key.added)}</span>
                    </div>
                    <div className="key-card-footer">
                      <button
                        className="button secondary button-small"
                        onClick={() => setModal({ type: "detail", key })}
                      >
                        Details
                      </button>
                      <div>
                        <button
                          className="button secondary button-small"
                          aria-label={`Copy public key for ${key.name}`}
                          onClick={() => copyPublicKey(key)}
                          disabled={Boolean(copyingKeyId)}
                        >
                          {copyingKeyId === key.id ? (
                            <LoaderCircle className="spin" size={15} />
                          ) : (
                            <Copy size={15} />
                          )}
                          {copyingKeyId === key.id
                            ? "Copying…"
                            : "Copy public key"}
                        </button>
                        <button
                          className="button secondary button-small"
                          aria-label={`Export public key for ${key.name}`}
                          onClick={() => exportKey(key, "public")}
                        >
                          <ArrowDownToLine size={15} />
                          Export
                        </button>
                        <button
                          className="icon-button delete-icon"
                          aria-label={`Delete key for ${key.name}`}
                          onClick={() => {
                            setError("");
                            setModal({ type: "delete", key });
                          }}
                        >
                          <Trash2 size={17} />
                        </button>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            )}
            {error && (
              <p className="workspace-error" role="alert">
                {error}
              </p>
            )}
          </>
        )}
      </main>
      {notice && (
        <div className="toast" role="status">
          <span>
            <Check size={15} />
          </span>
          {notice}
          <button
            className="icon-button"
            aria-label="Dismiss notification"
            onClick={() => setNotice("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
      {modal?.type === "add" && (
        <AddKeyModal
          initialMode={modal.mode}
          onClose={() => setModal(null)}
          onSaved={(key) => {
            setKeys((previous) => [
              key,
              ...previous.filter((item) => item.id !== key.id),
            ]);
            setDrafts((previous) => ({
              ...previous,
              encrypt: {
                ...previous.encrypt,
                keyId: key.canEncrypt ? key.id : previous.encrypt.keyId,
                output: "",
              },
              decrypt: {
                ...previous.decrypt,
                keyId: key.hasPrivate ? key.id : previous.decrypt.keyId,
                output: "",
              },
            }));
            setModal(null);
            setNotice("Key saved locally");
          }}
        />
      )}
      {modal?.type === "delete" && (
        <Modal
          title="Remove this key?"
          description={`“${modal.key.name}” will be removed from this device. Export a backup first if you need it later. This does not revoke the key.`}
          onClose={() => setModal(null)}
          busy={deleting}
        >
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
          <div className="modal-footer">
            <button
              className="button secondary"
              disabled={deleting}
              onClick={() => setModal(null)}
            >
              Keep key
            </button>
            <button
              className="button danger"
              onClick={() => deleteKey(modal.key)}
              disabled={deleting}
            >
              {deleting ? (
                <LoaderCircle className="spin" size={16} />
              ) : (
                <Trash2 size={16} />
              )}
              Remove key
            </button>
          </div>
        </Modal>
      )}
      {modal?.type === "detail" && (
        <Modal
          title={modal.key.name}
          description={modal.key.email || "PGP key details."}
          onClose={() => setModal(null)}
        >
          <dl className="key-details">
            <div>
              <dt>Key type</dt>
              <dd>
                {modal.key.hasPrivate
                  ? "Public + private key pair"
                  : "Public key"}
              </dd>
            </div>
            <div>
              <dt>Algorithm</dt>
              <dd>{modal.key.algorithm}</dd>
            </div>
            <div>
              <dt>Created</dt>
              <dd>{date(modal.key.created)}</dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>
                {modal.key.expires ? date(modal.key.expires) : "No expiration"}
              </dd>
            </div>
          </dl>
          <KeyInfoForm
            keyRecord={modal.key}
            onSaved={(key) => {
              setKeys((previous) =>
                previous.map((item) => (item.id === key.id ? key : item)),
              );
              setModal({ type: "detail", key });
            }}
          />
          <div className="detail-exports">
            <button
              className="button primary"
              onClick={() => copyPublicKey(modal.key)}
              disabled={Boolean(copyingKeyId)}
            >
              {copyingKeyId === modal.key.id ? (
                <LoaderCircle className="spin" size={16} />
              ) : (
                <Copy size={16} />
              )}
              {copyingKeyId === modal.key.id ? "Copying…" : "Copy public key"}
            </button>
            <button
              className="button secondary"
              onClick={() => exportKey(modal.key, "public")}
            >
              <ArrowDownToLine size={16} />
              Export public key
            </button>
            {modal.key.hasPrivate && (
              <button
                className="button secondary"
                onClick={() => exportKey(modal.key, "private")}
              >
                <ArrowDownToLine size={16} />
                Export private key
              </button>
            )}
            {modal.key.hasRevocation && (
              <button
                className="button secondary"
                onClick={() => exportKey(modal.key, "revocation")}
              >
                Download revocation certificate <ArrowDownToLine size={14} />
              </button>
            )}
          </div>
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
        </Modal>
      )}
      {modal?.type === "help" && (
        <Modal
          title="Help"
          description="Using keys and messages."
          onClose={() => setModal(null)}
        >
          <div className="help-sections">
            <div>
              <KeyRound size={21} />
              <section>
                <h3>Encrypt with their public key.</h3>
                <p>
                  Ask your contact for their public PGP key. Import it, choose
                  it in Messages, and encrypt what you want to say. Only their
                  matching private key can open it.
                </p>
              </section>
            </div>
            <div>
              <UnlockKeyhole size={21} />
              <section>
                <h3>Decrypt with your private key.</h3>
                <p>
                  Import your private key or generate a pair in the vault. Share
                  your public key with your contacts. To read their encrypted
                  messages, choose your private key, paste the message, and
                  decrypt. If an imported key has existing protection, unlock it
                  once during import.
                </p>
              </section>
            </div>
            <div>
              <HardDrive size={21} />
              <section>
                <h3>Everything stays local.</h3>
                <p>
                  Keys are saved to this project’s data/keys.json file, with
                  access restricted to your user account. Private keys are
                  stored unencrypted on this device. Messages are never saved.
                </p>
              </section>
            </div>
          </div>
          <div className="gentle-note">
            <FileKey2 size={20} />
            <p>
              Export a backup of your private key and keep it somewhere safe.
              There is no recovery service. Decryption alone doesn’t prove who
              sent a message.
            </p>
          </div>
          <button
            className="button primary full-width"
            onClick={() => setModal(null)}
          >
            Close
          </button>
        </Modal>
      )}
    </div>
  );
}
export default App;
