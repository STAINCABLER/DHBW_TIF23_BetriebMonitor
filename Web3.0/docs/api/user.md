# Benutzer-Schlüsselmaterial-API (Web3.0)

Die Endpunkte unter `/api/user/keypair` erlauben angemeldeten Personen, ihr kryptografisches Schlüsselmaterial einzusehen. Rotation und Widerruf sind derzeit deaktiviert und liefern HTTP 405. Zusätzlich stellt `/api/user/data/{publicKey}` einen lesenden Lookup-Endpunkt für Föderationspartner bereit.

- **Authentifizierung (Keypair):** Bearer-Token über `Authorization: Bearer <token>` erforderlich.
- **Ledger-Zugriff:** Für `/api/user/data/{publicKey}` muss ein gültiges Ledger-Token (`X-Ledger-Token`) vorliegen.
- **Schlüsselmaterial:** Der private Schlüssel wird verschlüsselt gespeichert (AES-GCM, optional Pepper via `USER_KEY_ENC_SECRET`).
- **Antwortformat:** Erfolgreiche Antworten liefern JSON-Objekte; Fehler folgen `{ "error": "Fehlermeldung" }`.

## GET `/api/user/keypair`

Gibt das aktuell gespeicherte Schlüsselmaterial zurück.

### Response 200 (Keypair Read)

```json
{
  "publicKey": "B64==",
  "createdAt": "2024-05-04T12:00:00+00:00",
  "encryptedPrivateKey": {
    "ciphertext": "...",
    "nonce": "...",
    "tag": "..."
  }
}
```

### Fehlerantworten (Keypair Read)

| Status | Grund |
| --- | --- |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Kein Schlüsselmaterial hinterlegt. |

## POST `/api/user/keypair`

Der Schlüsselwechsel ist deaktiviert. Der Server antwortet mit HTTP 405 und der Fehlermeldung `"Schlüsselwechsel ist deaktiviert"`.

## DELETE `/api/user/keypair`

Der Widerruf ist deaktiviert. Der Server antwortet mit HTTP 405 und der Fehlermeldung `"Schlüsselwiderruf ist deaktiviert"`.

## GET `/api/user/data/{publicKey}`

Stellt Grunddaten (IBAN, Vorname, Nachname, Bankname) zu einem Konto bereit. Der Endpunkt ist für föderierte Partnerbanken gedacht und erfordert ein gültiges Ledger-Token (`X-Ledger-Token`). Der Public Key muss Base64-kodiert übergeben werden.

### Response 200 (Public User Data)

```json
{
  "iban": "DE89...",
  "bankName": "AlteBank Web3.0",
  "firstName": "Max",
  "lastName": "Mustermann"
}
```

### Fehlerantworten (Public User Data)

| Status | Grund |
| --- | --- |
| 400 | Public Key fehlt oder ist ungültig kodiert. |
| 401 | Ledger-Token fehlt oder ist ungültig. |
| 404 | Kein Konto zum Public Key gefunden. |
| 503 | Der verwendete Store unterstützt den Lookup nicht. |

## Sicherheit & Hinweise

- **Token-Handling:** Für `/api/user/keypair` ist ein gültiges Bearer-Token nötig, für `/api/user/data/{publicKey}` ein Ledger-Token.
- **Audit Trail:** Der Server speichert lediglich das Schlüsselmaterial; Historisierung liegt beim Client.
- **Privatschlüssel:** Verlassen niemals den Server; Föderationspartner erhalten ausschließlich Metadaten.
