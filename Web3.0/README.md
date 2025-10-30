# Web3.0 – Vorbereitung Kryptografie & Föderation

Diese Stufe legt die Grundlagen für signierte Transaktionen und den späteren Föderationsbetrieb zwischen mehreren Bankinstanzen.

## Voraussetzungen

- Python 3.11 (oder neuer)
- Node.js 18.x inklusive `npm` für die SPA-Abhängigkeiten
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

> Hinweis: Das Projekt bringt zusätzlich ein POSIX-Skript `start.sh` mit. Unter Unix-ähnlichen Umgebungen (macOS, Linux, WSL) übernimmt es die vollständige Einrichtung:

```bash
./start.sh
```

Das Skript legt bei Bedarf das virtuelle Environment an, installiert Python- und npm-Abhängigkeiten und startet anschließend `server.py`. Unter Windows empfiehlt sich die Ausführung in WSL oder Git Bash; in Docker-Containern wird `start.sh` automatisch als Entry Point genutzt.

## Architekturüberblick

- **Flask-App (`server.py`)**: Enthält Bootstrapping, Store-Verwaltung (Memory/Upstash), Authentifizierung und Hilfsfunktionen.
- **Backend-Bibliotheken (`libaries/`)**: Beinhaltet die Blueprint-Pakete unter `libaries/api/` sowie kryptografische Utilities (`libaries/crypto_utils.py`). `register_apis` koppelt alle Blueprints an die Flask-App.
- **Start-Workflow (`start.sh`)**: Erstellt das virtuelle Environment, installiert Python- und npm-Dependencies und übergibt anschließend an den Flask-Server. Die Dockerfile ruft dieses Skript standardmäßig über `CMD` auf.
- **Frontend (`frontend/`)**: Single-Page-Anwendung (HTML, CSS, JS) inklusive Tests unter `frontend/assets/__tests__/`, ausgeliefert über Flask als statische Dateien.

## IBAN-Generierung

- Länderkennzeichen: immer `DE`.
- Bankleitzahl: fixes Präfix `04102025` (DHBW Banking-Demo).
- Kontonummer: zufällige, eindeutig überprüfte 10-stellige Nummer (mit führenden Nullen).
- Prüfziffer: dynamisch berechnet über das Modulo-97-Verfahren (ISO 7064). Der Server wiederholt die Generierung, bis `store.iban_exists` kein Duplikat meldet.

Damit ist jede erzeugte IBAN deterministisch aufgebaut (`DE{Prüfziffer}04102025{Kontonummer}`) und gleichzeitig eindeutig im Kontext der Demo-Bank.

## Umgebungsvariablen & Konfiguration

- Vorlage: `.env.example` (vollständig gruppierte Liste aller Variablen)
- Ausführliche Beschreibung inkl. Standardwerten & erwarteten Formaten: `docs/config/environment-variables.md`

Trage produktspezifische Werte in `.env` ein oder setze sie bei Deployments als echte Umgebungsvariablen.

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

Der resultierende Container führt beim Start automatisch `bash ./start.sh` aus. Dadurch werden sämtliche Abhängigkeiten installiert, bevor `server.py` gestartet wird.

Weitere Phasen (Kryptomodul, Ledger, Föderation) folgen auf dieser Basis.
