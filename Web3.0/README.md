# Web3.0 – Vorbereitung Kryptografie & Föderation

Diese Stufe legt die Grundlagen für signierte Transaktionen und den späteren Föderationsbetrieb zwischen mehreren Bankinstanzen.

## Voraussetzungen

- Python 3.11
- OpenSSL bzw. `mkcert` zum Erzeugen lokaler TLS-Zertifikate
- Optional: Docker zum Bauen des aktualisierten Images

## Installation (Lokal)

```powershell
cd Web3.0
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Relevante Umgebungsvariablen

Trage die Werte in `.env` ein (Vorlage: `.env.example`).

| Variable | Bedeutung |
| --- | --- |
| `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` | Zugangsdaten für Upstash Redis |
| `APP_SECRET_KEY` | Flask-Secret für Sessions |
| `INSTANCE_ID` | Eindeutiger Bezeichner dieser Bankinstanz (z. B. `altebank-dev`) |
| `INSTANCE_HOST` | Öffentliche URL/Hostname, den Partnerbanken verwenden |
| `INSTANCE_TLS_DIR` | Persistentes Verzeichnis, in dem Schlüssel & Zertifikate automatisch abgelegt werden |
| `USER_KEY_ENC_SECRET` | Optionales zusätzliches Secret für die Verschlüsselung von Nutzer-Schlüsseln |

## Nutzer-Schlüsselverwaltung

- Bei der Registrierung erzeugt der Server ein Ed25519-Schlüsselpaar.
- Der private Schlüssel wird mit dem Nutzerpasswort (Argon2id + AES-GCM) verschlüsselt und im Store abgelegt.
- Passwortrenews entschlüsseln den alten Schlüssel und verschlüsseln ihn mit dem neuen Passwort.
- API-Responses (`/api/auth/register`, `/api/auth/login`, `/api/accounts/me`) liefern das Public Key Material mit (`publicKey`, `keyCreatedAt`).

## Signierte Transaktionen

- Alle Kontobewegungen (`deposit`, `withdraw`, `transfer`) erwarten `timestamp` und `signature` im Request-Body.
- Die Signatur wird über den Kanon `json.dumps({"type", "sender", "receiver", "amount", "timestamp"}, sort_keys=True)` gebildet.
- `sender` entspricht dem Base64-codierten Public Key des anfragenden Nutzers, `receiver` dem Ziel (bei Auszahlungen `BANK_PUBLIC_KEY`).
- Ledger-Einträge und Konto-Transaktionen enthalten `transactionId`, `senderPublicKey`, `receiverPublicKey`, `signature` und den ISO-Zeitstempel.

## TLS-Testzertifikate

Für lokale Tests kannst du selbstsignierte Zertifikate generieren, z. B. mit OpenSSL:

```powershell
openssl req -x509 -nodes -newkey ed25519 -keyout instance.key -out instance.crt -days 365 \
  -subj "/CN=localhost"
```

Die erzeugten Dateien werden in `INSTANCE_TLS_DIR` abgelegt und bei Bedarf erneuert; stelle sicher, dass das Verzeichnis persistent gemountet ist.

## Docker Image bauen

```powershell
cd Web3.0
docker build -t altebank-web3 .
```

Weitere Phasen (Kryptomodul, Ledger, Föderation) folgen auf dieser Basis.
