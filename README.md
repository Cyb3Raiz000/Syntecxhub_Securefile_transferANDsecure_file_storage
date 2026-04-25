# 🔐 Secure File Vault

A single-file Python GUI application for **encrypted file storage and transfer** using military-grade cryptography — built with `tkinter` + `cryptography`.

---

## ✨ Features

- 🔒 **AES-256-GCM** encryption — confidentiality + per-chunk authentication tag
- ✅ **HMAC-SHA256** — file-level integrity verification
- 🔑 **PBKDF2-SHA256** — passphrase-to-key derivation (100,000 iterations)
- ⬡ **64 KB chunking** — handles large files with animated progress
- 🛡 **Chunk index AAD** — defeats reordering and replay attacks
- 🎲 **Unique 96-bit IV** per chunk via `os.urandom` — no IV reuse
- 🖥 **Dark GUI** — animated pipeline, chunk grid, password strength meter
- 📂 **Local vault** — encrypted files stored at `~/.secure_vault/`

---

## 📋 Requirements

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| cryptography | 41.0.0+ |
| tkinter | built-in |

---

## ⚡ Quick Start

```bash
# 1. Install dependency
pip install cryptography

# 2. Run
python secure_vault_gui.py
```

> `tkinter` ships with Python on Windows and macOS.  
> Linux: `sudo apt install python3-tk`

---

## 🖥 UI Overview

### Tab 1 — 🔑 Encrypt & Upload
| Element | Description |
|---|---|
| Drop zone | Click or drag-and-drop any file |
| Passphrase field | Live strength meter (Weak → Excellent) |
| Download folder | Where decrypted files are saved |
| Encrypt & Save | Encrypts file → stores in `~/.secure_vault/` |
| Decrypt File | Open any `.enc.json` vault file to decrypt |
| Pipeline steps | Visual: Key Derive → Chunking → AES-GCM → HMAC Sign → Store |
| Chunk grid | Animated squares showing each 64 KB chunk being encrypted |
| Security log | Real-time cryptographic operation log |

### Tab 2 — 🔐 Secure Vault
| Element | Description |
|---|---|
| Stats row | Total files, chunks, and storage size |
| File table | All encrypted files with name, size, chunk count, ID |
| Decrypt & Download | Re-derive key → verify HMAC → decrypt → save |
| Delete | Permanently wipes the `.enc.json` from vault |
| Detail bar | Shows full File ID, HMAC fingerprint, AES salt |

### Tab 3 — 🛡 Threat Model
Scrollable security analysis covering:
- Man-in-the-Middle (MitM)
- Data at rest / server compromise
- Brute-force / dictionary attacks
- Chunk reordering / replay
- IV/nonce reuse
- Key management & passphrase loss
- Timing oracle attacks
- Metadata leakage

---

## 🔐 Cipher Suite

```
passphrase + salt₁  ──PBKDF2-SHA256 (100k iter)──▶  AES-256 key
                                                            ↓
                         AES-GCM(IV, chunk, AAD=index)  →  ciphertext + 128-bit auth tag

passphrase + salt₂  ──PBKDF2-SHA256 (100k iter)──▶  HMAC-SHA256 key
                                                            ↓
                         HMAC(all ciphertext in chunk order)  →  256-bit MAC
```

- Two **independent** PBKDF2 derivations (separate salts) → AES key and HMAC key are unrelated
- **Authenticate-then-decrypt**: HMAC is always verified before any decryption begins
- GCM **auth tag** (128-bit) catches corruption per chunk
- HMAC-SHA256 catches file-level tampering and reordering

---

## 📁 Vault Storage

All encrypted files are stored in `~/.secure_vault/` as `.enc.json` files.

Each file contains:
```json
{
  "file_id":        "hex string",
  "filename":       "original_name.pdf",
  "mime_type":      "application/pdf",
  "plaintext_size": 123456,
  "aes_salt":       "hex (128-bit)",
  "hmac_salt":      "hex (128-bit)",
  "file_hmac":      "hex (256-bit)",
  "chunks": [
    { "index": 0, "iv": "hex (96-bit)", "ciphertext": "hex" },
    ...
  ]
}
```

> ⚠️ The **encryption key is never stored**. It is re-derived from your passphrase on every decrypt. Losing the passphrase = permanent data loss.

---

## 🛡 Threat Model Summary

| Threat | Severity | Mitigation |
|---|---|---|
| Man-in-the-Middle | 🔴 Critical | TLS 1.3 + GCM auth tag detects any bit-flip |
| Server/disk compromise | 🔴 Critical | Only ciphertext stored; key never persists |
| Brute-force passphrase | 🔴 Critical | PBKDF2 × 100k (→ Argon2id for production) |
| Chunk reordering/replay | 🟠 High | Chunk index bound as GCM AAD |
| IV/nonce reuse | 🟠 High | `os.urandom(12)` unique IV per chunk |
| Passphrase loss | 🟡 Medium | No recovery — use envelope encryption in prod |
| Timing oracle | 🟢 Low | `hmac.compare_digest()` constant-time compare |
| Metadata leakage | 🟢 Low | Encrypt filenames; pad chunk sizes in prod |

---

## 📂 Project Structure

```
secure_vault_gui.py     ← entire application (single file)
README.md               ← this file
~/.secure_vault/        ← encrypted vault (auto-created)
    ├── <id>.enc.json
    ├── <id>.enc.json
    └── ...
```

---

## ⚙️ Optional — Drag & Drop Support

Install `tkinterdnd2` for native file drag-and-drop:

```bash
pip install tkinterdnd2
```

Falls back gracefully to click-to-browse if not installed.

---

## 🚀 Production Hardening Checklist

- [ ] Replace PBKDF2 with **Argon2id** (memory-hard, GPU-resistant)
- [ ] Use **TLS 1.3** for any network transfer of `.enc.json` files
- [ ] Implement **envelope encryption** (RSA-wrapped AES key) for passphrase recovery
- [ ] Use **monotonic counter IV** instead of random to eliminate birthday bound risk
- [ ] Encrypt **filenames** — store as opaque IDs only
- [ ] Pad chunks to uniform size to hide file length metadata
- [ ] Add **key rotation** support (re-encrypt with new passphrase without decrypting to disk)

---

## 📜 License

MIT — free to use, modify, and distribute.
