# Admin-Transaktions-API (Web3.0)

Die folgenden Endpunkte dienen Administrations- und Testzwecken. Sie erlauben den Zugriff auf das globale Ledger sowie das manuelle Einspeisen von Transaktionen.

- **Basis-URL:** `/api/transactions`
- **Authentifizierung:** Erfordert den Header `X-Ledger-Token`. Der Wert muss exakt dem serverseitig konfigurierten `LEDGER_API_TOKEN` entsprechen. Ohne diesen Token sind die Endpunkte deaktiviert.
- **Antwortformat:** Erfolgsantworten liefern strukturierte JSON-Objekte, Fehler antworten mit `{ "error": "Fehlermeldung" }`.
- **Signaturen:** Alle Einträge im Ledger sollten eine gültige Ed25519-Signatur enthalten. Die Endpunkte unterstützen Signaturprüfung und Diagnosefunktionen.

## GET `/api/transactions`

Listet Ledger-Einträge paginiert auf. Optional können Ergebnisse auf eine Gegenpartei gefiltert werden.

### Query-Parameter

| Parameter | Typ | Beschreibung |
| --- | --- | --- |
| `limit` | integer | Anzahl der maximal zurückzugebenden Einträge (1–500, Standard 100). |
| `sinceId` | string | Liefert Einträge nach der angegebenen Transaktions-ID. Dient als Cursor für nachfolgende Seiten. |
| `partner` | string | Filtert auf Transaktionen, deren Sender*in oder Empfänger*in diesen Public Key besitzt. |

### Response 200 (Ledger List)

```json
{
  "transactions": [
    {
      "transactionId": "txn_...",
      "type": "deposit",
      "amount": "150.00",
      "senderPublicKey": "B64==",
      "receiverPublicKey": "B64==",
      "signature": "B64==",
      "timestamp": "2024-05-04T12:00:00+00:00",
      "metadata": {
        "source": "manual"
      }
    }
  ],
  "nextSinceId": "txn_..."
}
```

- `nextSinceId` wird nur gesetzt, wenn exakt `limit` Einträge geliefert wurden.

### Fehlerantworten (Ledger List)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder stimmt nicht mit `LEDGER_API_TOKEN` überein. |
| 503 | Ledger-API ist deaktiviert (kein `LEDGER_API_TOKEN` gesetzt). |

## GET `/api/transactions/export`

Gibt das vollständige Ledger als Liste zurück. Interne Paginierung wird serverseitig abgehandelt; Client-Anfragen benötigen keine zusätzlichen Parameter.

### Response 200 (Ledger Export)

```json
{
  "transactions": [
    {
      "transactionId": "txn_...",
      "type": "deposit",
      "amount": "150.00",
      "senderPublicKey": "B64==",
      "receiverPublicKey": "B64==",
      "signature": "B64==",
      "timestamp": "2024-05-04T12:00:00+00:00"
    }
  ]
}
```

### Fehlerantworten (Ledger Export)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 503 | Ledger-API ist deaktiviert. |

## PUT `/api/transactions/{transactionId}`

Legt einen Ledger-Eintrag mit der angegebenen ID an oder aktualisiert ihn. Bei bestehenden Einträgen muss `allowUpdate = true` gesetzt werden, sonst antwortet der Server mit `409 Konflikt`.

### Request-JSON (Ledger Upsert)

```json
{
  "type": "deposit",
  "amount": "150.00",
  "timestamp": "2024-05-04T12:00:00+00:00",
  "senderPublicKey": "B64==",
  "receiverPublicKey": "B64==",
  "signature": "B64==",
  "metadata": {
    "source": "manual"
  },
  "allowUpdate": false,
  "skipSignatureCheck": false
}
```

### Response 201/200 (Ledger Upsert)

```json
{
  "transactionId": "txn_123",
  "ledgerEntry": {
    "transactionId": "txn_123",
    "type": "deposit",
    "amount": "150.00",
    "senderPublicKey": "B64==",
    "receiverPublicKey": "B64==",
    "signature": "B64==",
    "timestamp": "2024-05-04T12:00:00+00:00",
    "metadata": {
      "source": "manual"
    }
  }
}
```

- Status `201` signalisiert einen neuen Eintrag, `200` eine erfolgreiche Aktualisierung.
- `skipSignatureCheck` sollte nur für Testfälle genutzt werden; ohne diese Option wird die Signatur verifiziert.

### Fehlerantworten (Ledger Upsert)

| Status | Grund |
| --- | --- |
| 400 | Ungültige Eingaben oder Signatur fehlgeschlagen. |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 409 | Transaktion existiert bereits und `allowUpdate` ist `false`. |
| 503 | Ledger-API ist deaktiviert. |

> **Hinweis:** POST-Anfragen auf `/api/transactions` werden mit HTTP 405 beantwortet (`"Ledger-Schreiboperationen nutzen PUT /api/transactions/{transactionId}"`).

## GET `/api/transactions/verify/{transactionId}`

Prüft die Signatur eines Ledger-Eintrags und liefert das Ergebnis.

### Response 200 (Ledger Verify)

```json
{
  "transactionId": "txn_...",
  "verified": true,
  "ledgerEntry": {
    "transactionId": "txn_...",
    "type": "deposit",
    "amount": "150.00",
    "senderPublicKey": "B64==",
    "receiverPublicKey": "B64==",
    "signature": "B64==",
    "timestamp": "2024-05-04T12:00:00+00:00"
  }
}
```

Bei ungültiger Signatur enthält die Antwort zusätzlich `"reason": "Signatur ungültig"`. Wenn Pflichtfelder fehlen, wird `verified = false` mit einer entsprechenden Begründung zurückgegeben.

### Fehlerantworten (Ledger Verify)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 404 | Transaktion nicht vorhanden. |
| 503 | Ledger-Storage nicht verfügbar oder Ledger-API deaktiviert. |

## Betriebs- und Sicherheitshinweise

- **Token-Handling:** Bewahre das konfigurierte `LEDGER_API_TOKEN` geheim. Ist kein Token hinterlegt, antworten die Endpunkte mit 503 und sind faktisch deaktiviert.
- **Signaturvalidierung:** Für verlässliche Ergebnisse sollten Tests `skipSignatureCheck = false` setzen. Nur für Negativtests darf die Prüfung übersprungen werden.
- **Ledger-Auswirkungen:** Ledger-Upserts erfassen nur Transaktionen im globalen Journal. Konto- oder Nutzerstände werden dadurch nicht automatisch angepasst.
- **Paginierung:** Nutze `nextSinceId`, um Folgeseiten abzurufen (`?sinceId=<value>`).
