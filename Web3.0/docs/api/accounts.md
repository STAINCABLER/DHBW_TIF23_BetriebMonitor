# Konto- und Transaktions-API (Web3.0)

Diese Dokumentation beschreibt alle Endpunkte unter `/api/accounts`. Sämtliche Endpunkte erwarten JSON, liefern JSON und verlangen ein gültiges Bearer-Token im Header (`Authorization: Bearer <token>`), sofern nicht anders angegeben.

- **Währung:** Beträge werden als Dezimalzahlen mit zwei Nachkommastellen verarbeitet. Serverantworten liefern Strings (z. B. `"123.45"`).
- **Zeitstempel:** ISO-8601 im UTC-Format (z. B. `"2024-05-04T12:00:00+00:00"`).
- **Signaturen:** Transaktionsendpunkte (`deposit`, `withdraw`, `transfer`) verlangen eine Ed25519-Signatur (Base64) über den definierten Payload.

## GET `/api/accounts/me`

Liefert Profilinformationen, Kontostand, Transaktionshistorie und Schlüsselmaterial der angemeldeten Person.

### Response 200 (Account Overview)

```json
{
  "accountId": "acct_ab12cd34",
  "email": "max@example.com",
  "firstName": "Max",
  "lastName": "Mustermann",
  "iban": "DE38...",
  "balance": "1024.50",
  "transactions": [
    {
      "transactionId": "txn_...",
      "type": "deposit",
      "amount": "100.00",
      "balance": "1024.50",
      "createdAt": "2024-05-04T12:00:00+00:00",
      "memo": "Einzahlung",
      "senderPublicKey": "B64==",
      "receiverPublicKey": "B64==",
      "signature": "B64=="
    }
  ],
  "advisor": {
    "id": "advisor_sven",
    "name": "Sven Meyer",
    "title": "Senior Kundenberater",
    "phone": "0711 204010",
    "email": "sven.meyer@altebank.de",
    "image": "assets/advisors/advisor-1.svg"
  },
  "publicKey": "B64==",
  "keyCreatedAt": "2024-05-04T12:00:00+00:00",
  "encryptedPrivateKey": {
    "ciphertext": "...",
    "nonce": "...",
    "tag": "..."
  },
  "bankPublicKey": "BANK_SYSTEM"
}
```

- `transactions` ist absteigend nach Erstellungsdatum sortiert und enthält alle verfügbaren Einträge (neueste zuerst).
- `advisor` wird automatisch gesetzt; falls kein Profil hinterlegt ist, weist der Server eins zu.
- `publicKey`/`encryptedPrivateKey` stammen aus dem Schlüsselspeicher; können `null` sein, falls noch nicht generiert.
- `bankPublicKey` enthält die serverseitige Kennung für Bank-zu-Bank-Transaktionen (z. B. `BANK_SYSTEM`).
- Bei Überweisungen ergänzt der Server Gegenparteifelder wie `counterpartyIban`, `counterpartyName` und `counterpartyPublicKey`.

### Fehlerantworten (Account Overview)

| Status | Grund |
| --- | --- |
| 401 | Token fehlt oder ist abgelaufen. |
| 404 | Konto konnte nicht geladen werden. |

## PUT `/api/accounts/me`

Aktualisiert Vorname, Nachname und E-Mail-Adresse.

### Request-JSON (Account Update)

```json
{
  "firstName": "Max",
  "lastName": "Mustermann",
  "email": "max@example.com"
}
```

| Feld | Pflicht | Beschreibung |
| --- | --- | --- |
| `firstName` | ja | Vorname (2-50 Zeichen, Buchstaben/Leerzeichen/`-`/`'`). |
| `lastName` | ja | Nachname (gleiche Regeln wie Vorname). |
| `email` | ja | Gültige, eindeutige E-Mail-Adresse. |

### Response 200 (Account Update)

```json
{
  "success": true
}
```

### Fehlerantworten (Account Update)

| Status | Grund |
| --- | --- |
| 400 | Validierungsfehler (`"Vorname enthält ungültige Zeichen"`, etc.). |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Konto nicht gefunden. |
| 409 | E-Mail existiert bereits bei einem anderen Konto. |

## DELETE `/api/accounts/me`

Löscht das angemeldete Konto dauerhaft.

### Request-JSON (Account Delete)

```json
{
  "confirmIban": "DE38..."
}
```

| Feld | Pflicht | Beschreibung |
| --- | --- | --- |
| `confirmIban` | ja | Muss exakt mit der gespeicherten IBAN übereinstimmen (ohne Leerzeichen). |

### Response 200 (Account Delete)

```json
{
  "success": true
}
```

- Aktive Sitzung wird invalidiert; das Token verliert sofort seine Gültigkeit.
- Schlüsselmaterial wird aus dem Store entfernt.

### Fehlerantworten (Account Delete)

| Status | Grund |
| --- | --- |
| 400 | IBAN fehlt oder stimmt nicht überein. |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Konto nicht gefunden. |
| 500 | Löschung im Store nicht möglich. |

## POST `/api/accounts/deposit`

Verbucht eine signierte Einzahlung auf das eigene Konto.

### Request-JSON (Deposit)

```json
{
  "amount": "150.00",
  "timestamp": "2024-05-04T12:00:00+00:00",
  "signature": "B64=="
}
```

| Feld | Pflicht | Beschreibung |
| --- | --- | --- |
| `amount` | ja | Positiver Betrag (> 0). |
| `timestamp` | ja | Zeitstempel, der in die Signatur einfließt. |
| `signature` | ja | Ed25519-Signatur (Base64) über den Nachrichtentext. |

### Signatur-Payload (Deposit)

```json
{
  "type": "deposit",
  "sender": "<userPublicKey>",
  "receiver": "<userPublicKey>",
  "amount": "150.00",
  "timestamp": "2024-05-04T12:00:00+00:00"
}
```

### Response 200 (Deposit)

```json
{
  "balance": "1174.50",
  "transactionId": "txn_..."
}
```

- Neue Transaktion wird sowohl im persönlichen Verlauf als auch im Ledger gespeichert.
- `balance` entspricht dem Kontostand nach Buchung.

### Fehlerantworten (Deposit)

| Status | Grund |
| --- | --- |
| 400 | Validierungsfehler oder ungültige Signatur. |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Konto nicht gefunden. |
| 500 | Schlüsselmaterial fehlt oder konnte nicht geladen werden. |

## POST `/api/accounts/withdraw`

Verbucht eine signierte Auszahlung.

### Request-JSON (Withdraw)

```json
{
  "amount": "150.00",
  "timestamp": "2024-05-04T12:00:00+00:00",
  "signature": "B64=="
}
```

Die Signatur wird über folgenden Payload erstellt:

```json
{
  "type": "withdraw",
  "sender": "<userPublicKey>",
  "receiver": "BANK_SYSTEM",
  "amount": "150.00",
  "timestamp": "2024-05-04T12:00:00+00:00"
}
```

Der Wert `BANK_SYSTEM` entspricht dem konfigurierten `BANK_PUBLIC_KEY` (Standard `BANK_SYSTEM`).

### Response 200 (Withdraw)

```json
{
  "balance": "874.50",
  "transactionId": "txn_..."
}
```

- Betrag wird vom Guthaben abgezogen; Ledger-Eintrag verwendet den absoluten Betrag.

### Fehlerantworten (Withdraw)

| Status | Grund |
| --- | --- |
| 400 | Validierung fehlgeschlagen oder Guthaben zu niedrig. |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Konto nicht gefunden. |
| 500 | Schlüsselmaterial fehlt oder konnte nicht geladen werden. |

## POST `/api/accounts/transfer`

Führt eine Überweisung von einem lokalen Konto zu einem anderen lokalen Konto aus.

### Request-JSON (Transfer)

```json
{
  "targetIban": "DE89...",
  "targetFirstName": "Erika",
  "targetLastName": "Mustermann",
  "amount": "250.00",
  "timestamp": "2024-05-04T12:00:00+00:00",
  "signature": "B64=="
}
```

| Feld | Pflicht | Beschreibung |
| --- | --- | --- |
| `targetIban` | ja | Vollständige IBAN des Zielkontos (nur DE-IBAN unterstützt). |
| `targetFirstName` | ja | Muss exakt mit dem gespeicherten Vornamen des Zielkontos übereinstimmen. |
| `targetLastName` | ja | Muss exakt mit dem gespeicherten Nachnamen des Zielkontos übereinstimmen. |
| `amount` | ja | Positiver Betrag (> 0). |
| `timestamp` | ja | Wird in die Signatur einbezogen. |
| `signature` | ja | Signatur mit `type = "transfer"`. |

### Signatur-Payload (Transfer)

```json
{
  "type": "transfer",
  "sender": "<sourcePublicKey>",
  "receiver": "<targetPublicKey>",
  "amount": "250.00",
  "timestamp": "2024-05-04T12:00:00+00:00"
}
```

### Response 200 (Transfer)

```json
{
  "balance": "624.50",
  "transactionId": "txn_..."
}
```

- Zwei Transaktionseinträge werden erzeugt: `transfer_out` für Sender*in, `transfer_in` für Empfänger*in.
- Gegenparteidaten (`counterpartyIban`, `counterpartyName`, `counterpartyPublicKey`) werden in beiden Richtungen gespeichert.

### Fehlerantworten (Transfer)

| Status | Grund |
| --- | --- |
| 400 | Validierungsfehler, inkonsistente Empfängerdaten oder ungültige Signatur. |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Sender- oder Empfängerkonto nicht gefunden. |
| 500 | Schlüsselmaterial fehlt oder Überweisungen nicht verfügbar. |

## POST `/api/accounts/resolve`

Liefert Basisdaten (Name, Public Key) zu einer IBAN, um Überweisungen vorzubereiten.

### Request-JSON (Resolve)

```json
{
  "targetIban": "DE89..."
}
```

### Response 200 (Resolve)

```json
{
  "accountId": "acct_zx90pq12",
  "firstName": "Erika",
  "lastName": "Mustermann",
  "publicKey": "B64==",
  "keyCreatedAt": "2024-05-04T12:00:00+00:00"
}
```

### Fehlerantworten (Resolve)

| Status | Grund |
| --- | --- |
| 400 | IBAN ungültig. |
| 401 | Token fehlt oder ist ungültig. |
| 404 | Konto zur IBAN nicht gefunden. |
| 500 | Zugriff auf Kontoinformationen nicht möglich. |

## Zusätzliche Hinweise

- **Ledger-Synchronisation:** Jeder erfolgreiche Vorgang erzeugt/aktualisiert Einträge im internen Ledger (`append_ledger_transaction` bzw. `upsert_ledger_transaction`).
- **Konfliktbehandlung:** Bei Duplikaten (z. B. wiederholtes Ledger-Append) sichert der Server die Idempotenz durch `upsert`-Fallback.
- **Sitzungs-TTL:** Sobald das Konto gelöscht oder die Sitzung abläuft, verlieren Tokens sofort ihre Gültigkeit. Weitere Anfragen führen zu 401.
- **IBAN-Format:** Alle vom Server erzeugten IBANs folgen dem Schema `DE{Prüfziffer}04102025{Kontonummer}`. Bei Eingaben erwartet die API eine deutsche IBAN (22 Stellen) und validiert sowohl die Prüfziffer als auch die Übereinstimmung mit den gespeicherten Bestandsdaten.
