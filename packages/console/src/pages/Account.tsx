import { useState } from "react";
import { formatKuna, seedToMnemonic } from "@kovanica/signer";

import { decryptBackup, encryptBackup, type BackupFile } from "../backup";
import { useSession } from "../session";
import { useAccountFigures } from "./figures";

export function Account() {
  const session = useSession();
  const figures = useAccountFigures();
  const [phrase, setPhrase] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [importText, setImportText] = useState("");

  async function create() {
    setError(null);
    const key = await session.createKey();
    setPhrase(seedToMnemonic(key.seed));
  }

  async function importSecret() {
    setError(null);
    setPhrase(null);
    try {
      const text = importText.trim();
      if (/^(0x)?[0-9a-fA-F]{64}$/.test(text)) {
        await session.importHex(text);
      } else {
        await session.importPhrase(text);
      }
      setImportText("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not import that key");
    }
  }

  async function downloadBackup() {
    if (!session.key) return;
    setError(null);
    try {
      const file = await encryptBackup(session.key.seed, passphrase, session.key.address);
      const blob = new Blob([JSON.stringify(file, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `kovanica-${session.network.id}-backup.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not encrypt the backup");
    }
  }

  async function onBackupFile(file: File | undefined, backupPassphrase: string) {
    if (!file) return;
    setError(null);
    try {
      const parsed = JSON.parse(await file.text()) as BackupFile;
      const seed = await decryptBackup(parsed, backupPassphrase);
      await session.importSeed(seed);
      seed.fill(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not open that backup");
    }
  }

  if (!session.key) {
    return (
      <section>
        <h1>Account</h1>
        <p className="lede">
          The key stays in this tab. Locking or closing the tab wipes it unless you saved a backup
          or the 24-word phrase.
        </p>
        {error ? <p className="error">{error}</p> : null}
        <div className="card">
          <h2>Create</h2>
          <button type="button" className="btn primary" onClick={() => void create()}>
            Create a key
          </button>
        </div>
        <ImportForm
          importText={importText}
          setImportText={setImportText}
          onImport={() => void importSecret()}
          onFile={(file, pass) => void onBackupFile(file, pass)}
        />
      </section>
    );
  }

  return (
    <section>
      <div className="page-head">
        <h1>Account</h1>
        <button type="button" className="btn" onClick={session.lock}>
          Lock
        </button>
      </div>
      <p className="mono address">{session.key.address}</p>
      {figures.error ? <p className="error">{figures.error}</p> : null}
      <div className="stats">
        <div className="stat">
          <div className="stat-label">Balance</div>
          <div className="stat-value">{figures.balance === null ? "—" : `${formatKuna(figures.balance)} KUNA`}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Nonce</div>
          <div className="stat-value">{figures.nonce === null ? "—" : figures.nonce.toString()}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Stake</div>
          <div className="stat-value">{figures.stake === null ? "—" : `${formatKuna(figures.stake)} KUNA`}</div>
        </div>
      </div>
      {phrase ? (
        <div className="card">
          <h2>Recovery phrase</h2>
          <p>Write these 24 words down. They are the same phrase `kovanica import-key` accepts. This page will not show them again.</p>
          <ol className="phrase">
            {phrase.split(" ").map((word, index) => (
              <li key={`${index}-${word}`}>{word}</li>
            ))}
          </ol>
          <button type="button" className="btn" onClick={() => setPhrase(null)}>
            I have stored the phrase
          </button>
        </div>
      ) : null}
      <div className="card">
        <h2>Encrypted backup</h2>
        <p className="muted">This file is for the console. It is not a CLI keystore.</p>
        <label>
          Passphrase
          <input
            type="password"
            value={passphrase}
            autoComplete="new-password"
            onChange={(event) => setPassphrase(event.target.value)}
          />
        </label>
        <button type="button" className="btn" onClick={() => void downloadBackup()}>
          Download backup
        </button>
      </div>
      {error ? <p className="error">{error}</p> : null}
    </section>
  );
}

function ImportForm({
  importText,
  setImportText,
  onImport,
  onFile,
}: {
  importText: string;
  setImportText: (value: string) => void;
  onImport: () => void;
  onFile: (file: File | undefined, passphrase: string) => void;
}) {
  const [backupPass, setBackupPass] = useState("");
  return (
    <div className="card">
      <h2>Import</h2>
      <label>
        32-byte hex seed or 24-word phrase
        <textarea value={importText} rows={3} onChange={(event) => setImportText(event.target.value)} />
      </label>
      <button type="button" className="btn" onClick={onImport}>
        Import
      </button>
      <label>
        Backup passphrase
        <input
          type="password"
          value={backupPass}
          autoComplete="current-password"
          onChange={(event) => setBackupPass(event.target.value)}
        />
      </label>
      <label>
        Backup file
        <input
          type="file"
          accept="application/json"
          onChange={(event) => onFile(event.target.files?.[0], backupPass)}
        />
      </label>
    </div>
  );
}
