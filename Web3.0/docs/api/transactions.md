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

## POST `/api/transactions`

Dieser Endpunkt ist derzeit read-only deaktiviert. Der Server beantwortet jeden Aufruf mit HTTP 405 und dem Hinweis `"Ledger kann nur gelesen werden"`.

### Fehlerantworten (Ledger Injection)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 405 | Ledger-Schreiboperationen sind deaktiviert. |
| 503 | Ledger-API ist deaktiviert (kein `LEDGER_API_TOKEN` gesetzt). |

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
- **Ledger-Auswirkungen:** POST-Aufrufe ändern ausschließlich das Ledger. Kontostände oder Nutzertransaktionen werden dadurch nicht automatisiert angepasst.
- **Paginierung:** Nutze `nextSinceId`, um Folgeseiten abzurufen (`?sinceId=<value>`).
