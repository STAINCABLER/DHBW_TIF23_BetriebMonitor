# AlteBank Web3.0 – Umgebungsvariablen

Die Flask-Anwendung lädt beim Start `.env` (via `python-dotenv`) und liest anschließend die unten dokumentierten Variablen. Nicht gesetzte Werte fallen auf die jeweils angegebenen Defaults zurück. Alle Werte werden als Strings aus `os.getenv` gelesen; numerische Angaben müssen daher als parsebare Zeichenketten hinterlegt werden.

## 1. Sicherheits- & Zugriffstokens

| Variable | Standardwert | Format | Beschreibung |
| --- | --- | --- | --- |
| `APP_SECRET_KEY` | zufällig (32 hex Zeichen) | Hex- oder beliebiger String | Signiert Flask-Sessions; leer lassen nur zu Testzwecken. |
| `LEDGER_API_TOKEN` | `""` (Ledger deaktiviert) | Beliebiger String | Erwarteter Wert von `X-Ledger-Token` bei Föderations-/Ledger-Aufrufen. |
| `AUTH_TRANS_TOKEN` | `""` (Token deaktiviert) | Beliebiger String | Erwarteter Wert von `X-Auth-Trans-Token` für interne Transaktions-APIs. |
| `USER_KEY_ENC_SECRET` | `""` (kein Pepper) | Beliebiger String | Optionaler zusätzlicher Pepper für die AES-Verschlüsselung privater Schlüssel. |

## 2. Bankidentität & Mandantenkontext

| Variable | Standardwert | Format | Beschreibung |
| --- | --- | --- | --- |
| `INSTANCE_ID` | `HOSTNAME` oder `node_<hex>` | Kurzer, eindeutiger String | Kennzeichnet die Bankinstanz innerhalb eines Verbunds. |
| `BANK_NAME` | `AlteBank Web3.0` | Freitext | Anzeigename der Bank für API-Antworten. |
| `BANK_PUBLIC_KEY` | `BANK_SYSTEM` | Freitext | Öffentlicher Schlüssel der Bank für Signaturen/Identifikation. |
| `FQDN_ALTEBANK` | `""` | Vollständiger Domainname | Genutzt für URL-Konstruktion, falls keine Basis-URL gesetzt ist. |

## 3. Netzwerk, Routing & Basis-URLs

| Variable | Standardwert | Format | Beschreibung |
| --- | --- | --- | --- |
| `PUBLIC_BASE_URL` | `""` | Vollständige HTTPS/HTTP-URL | Erzwingt die öffentliche Basis-URL (inkl. Schema & Port). |
| `CONTROL_BASE_URL` | `""` | Vollständige HTTPS/HTTP-URL | Überschreibt die Kontroll-/Verwaltungs-URL, falls sie von der öffentlichen abweicht. |
| `PUBLIC_BASE_SCHEME` | `https` | `http` oder `https` | Schema, falls `PUBLIC_BASE_URL` fehlt. |
| `PUBLIC_HOST` | externe IP oder `127.0.0.1` | Hostname / IP | Host für automatisch generierte öffentliche URLs. |
| `PUBLIC_PORT` | `PORT` oder `8000` | Portnummer als String | Öffentlicher Port; bei `443` entfällt die Port-Komponente. |
| `PORT` | `8000` | Portnummer als String | Bindet den Flask-Server (z. B. `5000`, `8000`). |
| `EXTERNAL_IP_OVERRIDE` | `127.0.0.1` | IPv4 / IPv6 | Erzwingt eine bestimmte externe IP, falls Lookup scheitert. |
| `EXTERNAL_IP_LOOKUP_ENDPOINTS` | `https://api.ipify.org,https://ifconfig.me/ip` | CSV-Liste von URLs | Reihenfolge der Dienste zur Ermittlung der externen IP. |

## 4. Sitzungen & Hintergrundjobs

| Variable | Standardwert | Format | Beschreibung |
| --- | --- | --- | --- |
| `SESSION_TTL_SECONDS` | `3600` | Integer (Sekunden) | Gültigkeitsdauer neu ausgestellter API-Sessions. |
| `SESSION_CLEANUP_INTERVAL_SECONDS` | `600` | Integer (Sekunden) | Intervall der Hintergrundbereinigung abgelaufener Sessions. |
| `LEDGER_SYNC_INTERVAL_SECONDS` | `60` | Integer (Sekunden) | Wartezeit zwischen Ledger-Synchronisationsläufen. |
| `INSTANCE_HEARTBEAT_INTERVAL_SECONDS` | `120` | Integer (Sekunden) | Frequenz, mit der Instanz-Heartbeats gesendet werden. |
| `INSTANCE_STALE_THRESHOLD_SECONDS` | `600` | Integer (Sekunden) | Zeitraum, nach dem ausbleibende Heartbeats Instanzen als „stale“ markieren. |
| `INSTANCE_STALE_GRACE_SECONDS` | `300` | Integer (Sekunden) | Nachfrist, bevor eine „stale“-Instanz endgültig als offline gilt. |
| `CONTROL_HEALTH_INTERVAL_SECONDS` | `60` | Integer (Sekunden) | Prüfintervall für Control-Node-Gesundheitschecks. |

## 5. Föderation & Ledger-Sync

| Variable | Standardwert | Format | Beschreibung |
| --- | --- | --- | --- |
| `LEDGER_NODE_ADDRESSES` | `""` | CSV, Einträge `token@https://host` oder `https://host` | Liste bekannter Ledger-Knoten für manuelle Registrierung. |
| `LEDGER_SYNC_TARGETS` | `""` | CSV, Einträge `token@https://host` oder `https://host` | Ausgangspunkte für automatische Ledger-Synchronisation; jeder Eintrag kann weitere Knoten liefern. |

## 6. Datenhaltung & Speicher

| Variable | Standardwert | Format | Beschreibung |
| --- | --- | --- | --- |
| `UPSTASH_REDIS_REST_URL` | `""` | HTTPS-URL | Upstash REST-Endpunkt (z. B. `https://eu1-broad-...`). |
| `UPSTASH_REDIS_REST_TOKEN` | `""` | Bearer-Token | Upstash API-Token passend zur REST-URL. |
| `REDIS_URL` | `""` | `redis://` oder `rediss://` URL | Alternative Konfiguration; wird zur Ableitung der REST-Zugangsdaten genutzt, falls REST-Werte fehlen. |

## 7. Laufzeit, Debug & Sonstiges

| Variable | Standardwert | Format | Beschreibung |
| --- | --- | --- | --- |
| `FLASK_ENV` | `""` | `development` oder `production` | Aktiviert Entwicklungsmodus (Debug-Toolbar etc.). |
| `FLASK_DEBUG` | `""` | `0`, `1`, `false`, `true` | Überschreibt Flask-Debug-Flag unabhängig von `FLASK_ENV`. |
| `INSTANCE_TLS_DIR` | `./data/tls` (Docker-Defaults) | Pfad | Persistenter Speicherort für Schlüssel/Zertifikate (genutzt in Container-Workflows). |

### Hinweise zur CSV-Syntax

CSV-Listen (`LEDGER_NODE_ADDRESSES`, `LEDGER_SYNC_TARGETS`, `EXTERNAL_IP_LOOKUP_ENDPOINTS`) akzeptieren kommagetrennte Einträge. Jeder Eintrag darf Leerzeichen enthalten; führende/trailende Whitespaces werden entfernt. Token können inline vorangestellt werden (`<token>@https://host`), ansonsten greift die globale Vorgabe `LEDGER_API_TOKEN`.

### Priorität & Fallbacks

1. Werte in der laufenden Umgebung überschreiben `.env`.
2. Fehlt `PUBLIC_BASE_URL`, konstruiert der Server URLs aus Schema (`PUBLIC_BASE_SCHEME`), Host (`PUBLIC_HOST`) und Port (`PUBLIC_PORT`).
3. Ohne `UPSTASH_REDIS_*`-Angaben wird automatisch der In-Memory-Store (`MemoryStore`) verwendet.
4. Ist kein `LEDGER_API_TOKEN` gesetzt, beantworten Ledger-Routen mit HTTP 503.
