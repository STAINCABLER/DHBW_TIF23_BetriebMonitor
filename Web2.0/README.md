# AlteBank Web 2.0

Modernisiertes Online-Banking-Demo, das einen Flask-Backend mit einem interaktiven Frontend kombiniert und Kontodaten in Upstash Redis persistiert.

## Features

- Responsives Single-Page-Interface mit moderner 2020-Optik.
- Registrierung, Login, Logout sowie Einzahlungen, Auszahlungen und Überweisungen.
- Token-basierte Sessions mit konfigurierbarer Lebensdauer.
- Transaktionshistorie und Saldenverwaltung in Upstash Redis (Fallback auf In-Memory-Store für lokale Tests).
- Automatisch generierte, eindeutige IBAN pro Konto mit Copy-Funktion und Empfängerprüfung bei Überweisungen.
- Transaktionsliste aktualisiert sich automatisch im Dashboard ohne manuelles Neuladen.
- Serverseitige Prüfung verhindert Überziehungen bei Auszahlungen und Überweisungen.

## Schnellstart

1. **Umgebung vorbereiten**

   ```bash
   cd Web2.0
   cp .env.example .env
   ```

2. **Upstash Redis**
   - Erstelle eine Redis-Instanz bei [Upstash](https://upstash.com/).
   - Trage die Werte für `UPSTASH_REDIS_REST_URL` und `UPSTASH_REDIS_REST_TOKEN` in `.env` ein (siehe Dashboard).
   - Optional: Hinterlege zusätzlich `REDIS_URL`, dann werden REST-Werte automatisch abgeleitet.
   - Lege einen individuellen `APP_SECRET_KEY` fest.

3. **Lokalen Server starten**

   ```bash
   pip install -r requirements.txt
   python server.py
   ```

   Die App läuft anschließend unter <http://localhost:8000>.

## Docker

```bash
docker build -t altebank-web2 .
docker run --rm -p 8000:8000 --env-file .env altebank-web2
```

## API Überblick

| Methode | Route                    | Beschreibung                        |
|---------|--------------------------|-------------------------------------|
| POST    | `/api/auth/register`     | Konto anlegen und Session erhalten  |
| POST    | `/api/auth/login`        | Login mit E-Mail/Passwort           |
| POST    | `/api/auth/logout`       | Session invalidieren                |
| GET     | `/api/accounts/me`       | Aktuellen Kontostand und Historie   |
| POST    | `/api/accounts/deposit`  | Guthaben erhöhen                    |
| POST    | `/api/accounts/withdraw` | Guthaben reduzieren (mit Prüfung)   |
| POST    | `/api/accounts/transfer` | Überweisung auf bestehendes Konto   |

Sämtliche geschützte Endpunkte erwarten den `Authorization: Bearer <token>` Header.

### Hinweis zu Payloads

- `POST /api/auth/register` erwartet `email`, `password`, `firstName`, `lastName` sowie optional `initialDeposit`.
- `POST /api/auth/login` erwartet `email` und `password`.
- `POST /api/accounts/transfer` erwartet `targetIban`, `targetFirstName`, `targetLastName` und `amount`. IBAN und Name müssen übereinstimmen, andernfalls wird die Überweisung abgelehnt.

## Entwicklungstipps

- Setze `SESSION_TTL_SECONDS` in der `.env`, um Session-Zeiten anzupassen.
- Ohne Upstash-Konfiguration nutzt der Server einen In-Memory-Store; ideal für lokale Tests, aber nicht persistent.
- Für Debug-Ausgaben kann `FLASK_ENV=development` ergänzt werden.

## Tests

```powershell
cd Web2.0
pip install -r requirements.txt
pytest tests
```

Die Suite fokussiert sich auf zentrale API-Flows (Registrierung, Login, Ein-/Auszahlungen, Überweisungen) und nutzt den `MemoryStore` für deterministische Ergebnisse.

## Lizenz

Siehe [LICENSE](../LICENSE).
