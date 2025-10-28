# Benutzer-Schlüsselmaterial-API (Web3.0)

Die Endpunkte unter `/api/user/keypair` ermöglichen es angemeldeten Personen, ihr kryptografisches Schlüsselmaterial einzusehen, zu rotieren oder zu widerrufen. Alle Aufrufe benötigen ein gültiges Bearer-Token im Header (`Authorization: Bearer <token>`).

- **Passwortprüfung:** Für Mutationen (`POST`, `DELETE`) muss das aktuelle Login-Passwort übermittelt werden.
- **Schlüsselmaterial:** Der private Schlüssel wird serverseitig ausschließlich verschlüsselt gespeichert (AES-GCM, optional Pepper über `USER_KEY_ENC_SECRET`).
- **Antwortformat:** Erfolgreiche Antworten liefern strukturierte JSON-Objekte, Fehler folgen `{ "error": "Fehlermeldung" }`.

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

Erzeugt ein neues Schlüsselpaar und ersetzt das bestehende.

### Request-JSON (Keypair Rotate)

```json
{
  "password": "Secret123",
  "exposePrivateKey": false
}
```

| Feld | Pflicht | Beschreibung |
| --- | --- | --- |
| `password` | ja | Aktuelles Login-Passwort; wird zur Authentifizierung und für die Verschlüsselung genutzt. |
| `exposePrivateKey` | optional | Wenn `true`, liefert die Antwort den neuen Private Key (Base64-kodiert) für Testzwecke. Standard `false`. |

### Response 201 (Keypair Rotate)

```json
{
  "publicKey": "B64==",
  "createdAt": "2024-05-04T12:05:00+00:00",
  "encryptedPrivateKey": {
    "ciphertext": "...",
    "nonce": "...",
    "tag": "..."
  },
  "previousPublicKey": "B64==",
  "privateKey": "BASE64-OPTIONAL"
}
```

- `previousPublicKey` zeigt den zuvor aktiven Schlüssel an.
- Das Feld `privateKey` ist nur enthalten, wenn `exposePrivateKey = true` übermittelt wurde.

### Fehlerantworten (Keypair Rotate)

| Status | Grund |
| --- | --- |
| 400 | Passwort ist falsch oder Pflichtfelder fehlen. |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Konto nicht gefunden. |

## DELETE `/api/user/keypair`

Hebt das gespeicherte Schlüsselmaterial auf. Beim nächsten Login wird ein neues Paar erzeugt.

### Request-JSON (Keypair Delete)

```json
{
  "password": "Secret123"
}
```

### Response 200 (Keypair Delete)

```json
{
  "success": true,
  "revokedPublicKey": "B64=="
}
```

### Fehlerantworten (Keypair Delete)

| Status | Grund |
| --- | --- |
| 400 | Passwort ist falsch. |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Konto oder Schlüsselmaterial nicht vorhanden. |

## Sicherheit & Hinweise

- **Passwortvalidierung:** Alle mutierenden Aufrufe validieren das aktuelle Passwort über `_verify_password`.
- **Audit Trail:** Der Server speichert lediglich das neue Schlüsselmaterial; eventuelle Historisierung muss clientseitig erfolgen.
- **Privatschlüssel:** Die Rückgabe des privaten Schlüssels dient ausschließlich Testzwecken – in Produktionskontexten sollte `exposePrivateKey` deaktiviert bleiben.
