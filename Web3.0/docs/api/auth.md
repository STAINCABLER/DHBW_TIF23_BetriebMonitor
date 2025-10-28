# Authentifizierungs-API (Web3.0)

- **Authentifizierung:** Nicht erforderlich für `register` und `login`, ansonsten Bearer-Token im `Authorization`-Header (`Authorization: Bearer <token>`).
- **Antwortformat:** Erfolgsantworten enthalten Datenobjekte, Fehlerantworten folgen dem Schema `{ "error": "Fehlermeldung" }`.
- **Zeichensatz:** UTF-8. Zahlen werden als Strings mit Punktnotation (z. B. `"10.50"`) übertragen.
- Ledger-spezifische Operationen nutzen ausschließlich das serverseitig konfigurierte `LEDGER_API_TOKEN`; es wird nicht an Clients herausgegeben.

## POST `/api/auth/register`

Erstellt ein neues Girokonto, erzeugt automatisch Schlüsselmaterial und meldet die Nutzerin/den Nutzer an.

### Request-Daten

```json
{
  "email": "max@example.com",
  "password": "geheim123",
  "firstName": "Max",
  "lastName": "Mustermann",
  "initialDeposit": "250.00"
}
```

| Feld | Typ | Pflicht | Beschreibung |
| --- | --- | --- | --- |
| `email` | string | ja | Gültige E-Mail-Adresse; muss eindeutig sein. |
| `password` | string | ja | Mindestens 6 Zeichen; keine weiteren Restriktionen. |
| `firstName` | string | ja | Vorname (2-50 Zeichen, Buchstaben/Leerzeichen/`-`/`'`). |
| `lastName` | string | ja | Nachname (gleiche Regeln wie Vorname). |
| `initialDeposit` | string/number | optional | Startguthaben ≥ 0; wird als Einzahlung verbucht, wenn > 0. |

### Response 200 (Register)

```json
{
  "token": "session-token",
  "firstName": "Max",
  "lastName": "Mustermann",
  "iban": "DE38...",
  "publicKey": "B64==",
  "keyCreatedAt": "2024-05-04T12:00:00+00:00",
  "encryptedPrivateKey": {
    "ciphertext": "...",
    "nonce": "...",
    "tag": "..."
  },
  "advisor": {
    "id": "advisor_sven",
    "name": "Sven Meyer",
    "title": "Senior Kundenberater",
    "phone": "0711 204010",
    "email": "sven.meyer@altebank.de",
    "image": "assets/advisors/advisor-1.svg"
  }
}
```

- `token`: Direkt nutzbares Bearer-Token (TTL: `SESSION_TTL_SECONDS`, Standard 3600s).
- `publicKey`/`encryptedPrivateKey`: Vom System erzeugtes Schlüsselpaar; private Komponente ist mit dem angegebenen Passwort verschlüsselt.
- `LEDGER_API_TOKEN` verbleibt serverseitig – Client-Anwendungen erhalten keinen Ledger-Token mehr über die Auth-Flows.
- Bei `initialDeposit` > 0 wird automatisch eine signierte Einzahlung `deposit` erstellt und der Kontostand angepasst.

### Fehlerantworten (Register)

| Status | Grund |
| --- | --- |
| 400 | Ungültige oder fehlende Eingaben (`"E-Mail existiert bereits"`, `"Ungültige IBAN"`, …). |
| 409 | Konflikt, wenn E-Mail bereits registriert ist. |
| 500 | Interner Fehler beim Erstellen des Kontos oder Schlüsselmaterials. |

## POST `/api/auth/login`

Meldet eine registrierte Person an und liefert vorhandenes Schlüsselmaterial.

### Request-Payload

```json
{
  "email": "max@example.com",
  "password": "geheim123"
}
```

### Response 200 (Login)

```json
{
  "token": "session-token",
  "firstName": "Max",
  "lastName": "Mustermann",
  "iban": "DE38...",
  "publicKey": "B64==",
  "keyCreatedAt": "2024-05-04T12:00:00+00:00",
  "encryptedPrivateKey": {
    "ciphertext": "...",
    "nonce": "...",
    "tag": "..."
  }
}
```

- Falls kein Schlüsselmaterial vorhanden ist (Migration), wird eines erstellt und sofort zurückgegeben.
- `publicKey`, `keyCreatedAt` und `encryptedPrivateKey` können `null` sein, falls das Konto noch kein Schlüsselmaterial aufgebaut hat.

### Fehlerantworten (Login)

| Status | Grund |
| --- | --- |
| 400 | Ungültige Eingaben (z. B. zu kurzes Passwort). |
| 401 | Falsche Anmeldedaten (`"Ungültige Zugangsdaten"`). |
| 500 | Konto beschädigt oder Schlüsselgenerierung fehlgeschlagen. |

## POST `/api/auth/logout`

Beendet die aktuelle Sitzung. Erfordert ein gültiges Bearer-Token.

### Response 200 (Logout)

```json
{
  "success": true,
  "username": "acct_ab12cd34"
}
```

### Fehlerantworten (Logout)

| Status | Grund |
| --- | --- |
| 401 | Token fehlt oder ist abgelaufen. |

## PUT `/api/auth/password`

Ändert das Passwort der angemeldeten Person und re-encryptet das Schlüsselmaterial.

### Request-JSON

```json
{
  "currentPassword": "geheim123",
  "newPassword": "superSicher456",
  "confirmPassword": "superSicher456"
}
```

| Feld | Pflicht | Beschreibung |
| --- | --- | --- |
| `currentPassword` | ja | Muss mit der aktuellen Passwort-Hash übereinstimmen. |
| `newPassword` | ja | Mindestlänge 6 Zeichen; darf identisch mit `currentPassword` sein. |
| `confirmPassword` | optional | Falls gesetzt, muss genau `newPassword` entsprechen. |

### Response 200 (Passwort aktualisieren)

```json
{
  "success": true
}
```

- Das bestehende Schlüsselmaterial wird entschlüsselt (`currentPassword`) und mit dem neuen Passwort erneut verschlüsselt.
- Falls kein Schlüsselmaterial existiert, wird automatisch eines erzeugt.

### Fehlerantworten (Passwort aktualisieren)

| Status | Grund |
| --- | --- |
| 400 | Validierungsfehler (`"Neue Passwörter stimmen nicht überein"`, `"Aktuelles Passwort ist falsch"`, …). |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Konto wurde nicht gefunden. |
| 500 | Schlüssel konnte nicht entschlüsselt oder gespeichert werden. |

## Sicherheitshinweise

- **Token-Gültigkeit:** `SESSION_TTL_SECONDS` (Default: 3600s). Session-Cleanup läuft periodisch und entfernt abgelaufene Tokens serverseitig.
- **Passwort-Hashes:** SHA-256 mit per-User-Salt (`salt`).
- **Schlüsselverschlüsselung:** AES-GCM via `encrypt_private_key`, optional mit Pepper (`USER_KEY_ENC_SECRET`).
- **Fehlertexte:** Deutschsprachig, keine technischen Details. Bei Validierungsfehlern stets HTTP 400, bei Konflikten 409, bei nicht authentifiziertem Zugriff 401.
