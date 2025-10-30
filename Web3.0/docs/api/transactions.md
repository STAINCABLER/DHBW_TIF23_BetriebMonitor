# Transactions API

Die Transaktions-API stellt alle öffentlich erreichbaren Endpunkte bereit, um das Ledger der Bank zu inspizieren, neue eingehende Zahlungen anderer Institute zu erfassen und vorhandene Einträge zu verifizieren. Sämtliche Endpunkte sind derzeit ohne Token nutzbar. Zukünftige Versionen können Authentifizierung ergänzen; Clients sollten entsprechende Erweiterungen berücksichtigen.

Alle Beträge werden als String mit zwei Nachkommastellen im Dezimalformat (`"123.45"`) übertragen. Zeitstempel folgen ISO-8601 (`YYYY-MM-DDTHH:MM:SS.sssZ`). Signaturen nutzen das im Benutzerkonto hinterlegte Schlüsselpaar und werden Base64-kodiert.

---

## GET `/api/transactions`

Liefert eine generierte Übersicht über die verfügbaren Transaktions-Endpunkte dieser Instanz. Dieser Einstiegspunkt eignet sich für Service-Discovery sowie für Monitoring-Tools.

### Beispielantwort (Transaktionsübersicht)

```json
{
    "generatedAt": "2025-10-28T12:00:00.123456+00:00",
    "endpoints": [
        {
            "method": "GET",
            "path": "/api/transactions",
            "url": "https://bank.example/api/transactions",
            "description": "Listet sämtliche verfügbaren Transaktions-Endpunkte dieser Instanz auf."
        },
        {
            "method": "GET",
            "path": "/api/transactions/export",
            "url": "https://bank.example/api/transactions/export",
            "description": "Listet verfügbare Export-Varianten (vollständig vs. paginiert)."
        },
        {
            "method": "POST",
            "path": "/api/transactions/{transactionId}",
            "url": "https://bank.example/api/transactions/{transactionId}",
            "description": "Empfängt eingehende Transaktionen anderer Institute und legt sie im Ledger ab."
        },
        {
            "method": "GET",
            "path": "/api/transactions/verify/{transactionId}",
            "url": "https://bank.example/api/transactions/verify/{transactionId}",
            "description": "Prüft eine vorhandene Ledger-Transaktion auf Gültigkeit der Signatur."
        }
    ]
}
```

Feldbeschreibung:

- `generatedAt`: Zeitpunkt der Generierung der Übersicht (UTC).
- `endpoints`: Liste der Endpunkt-Metadaten.

---

## GET `/api/transactions/export`

Discovery-Endpunkt, der alle Exportvarianten auflistet. Ideal für Clients, die dynamisch entscheiden möchten, ob sie einen kompletten Dump oder die paginierte Variante beziehen.

### Beispielantwort (Export-Discovery)

```json
{
    "generatedAt": "2025-10-28T12:10:00.000000+00:00",
    "exports": [
        {
            "path": "/api/transactions/export/all",
            "url": "https://bank.example/api/transactions/export/all",
            "description": "Gibt das vollständige Ledger als einmaligen JSON-Dump zurück."
        },
        {
            "path": "/api/transactions/export/stream",
            "url": "https://bank.example/api/transactions/export/stream",
            "description": "Liefert das Ledger paginiert (Parameter: limit, sinceId)."
        }
    ]
}
```

Feldbeschreibung:

- `generatedAt`: Zeitpunkt der Generierung (UTC).
- `exports`: Liste der Export-Varianten mit Pfad, absoluter URL und Beschreibung.

---

## GET `/api/transactions/export/all`

Gibt das komplette Ledger als JSON zurück – identisch zum früheren Verhalten des Export-Endpunkts. Nicht paginiert, daher bei sehr großen Datenmengen entsprechend ressourcenintensiv.

### Beispielantwort (Vollständiger Export)

```json
{
    "exportedAt": "2025-10-28T12:00:05.654321+00:00",
    "count": 120,
    "transactions": [
        {
            "transactionId": "txn_abc123",
            "type": "deposit",
            "amount": "42.00",
            "senderPublicKey": "BASE64==",
            "receiverPublicKey": "BASE64==",
            "signature": "BASE64SIG==",
            "timestamp": "2025-10-01T09:12:34+00:00",
            "metadata": {
                "source": "external-ledger"
            }
        }
    ]
}
```

Feldbeschreibung:

- `exportedAt`: Zeitpunkt der Exporteerstellung (UTC).
- `count`: Anzahl der gelieferten Ledger-Einträge.
- `transactions`: Liste der Transaktionen in Einfüge-Reihenfolge.

---

## GET `/api/transactions/export/stream`

Paginiert das Ledger. Unterstützt zwei Query-Parameter:

- `limit` (optional, Standard `200`, Bereich `1..500`)
- `sinceId` (optional, letzte bekannte `transactionId`, ab der weitergelesen werden soll)

### Beispielantwort (Paginierter Export)

```json
{
    "exportedAt": "2025-10-28T12:05:00.000000+00:00",
    "limit": 2,
    "sinceId": "txn_abc120",
    "nextSinceId": "txn_abc122",
    "count": 2,
    "transactions": [
        {
            "transactionId": "txn_abc121",
            "type": "deposit",
            "amount": "12.00",
            "senderPublicKey": "BASE64==",
            "receiverPublicKey": "BASE64==",
            "signature": "BASE64SIG==",
            "timestamp": "2025-10-02T08:00:00+00:00"
        },
        {
            "transactionId": "txn_abc122",
            "type": "withdraw",
            "amount": "5.00",
            "senderPublicKey": "BASE64==",
            "receiverPublicKey": "BASE64==",
            "signature": "BASE64SIG==",
            "timestamp": "2025-10-02T08:05:00+00:00"
        }
    ]
}
```

Feldbeschreibung:

- `limit`: Genutzter Limitwert für diese Seite.
- `sinceId`: Startpunkt der Abfrage (kann `null` sein).
- `nextSinceId`: Cursor für die nächste Seite (`null`, wenn keine weiteren Daten verfügbar sind).
- `count`: Anzahl der gelieferten Elemente auf dieser Seite.
- `transactions`: Ergebnis-Liste.

---

## POST `/api/transactions/{transactionId}`

Empfängt eingehende Transaktionen anderer Banken. Die `transactionId` in der URL muss eindeutig sein. Bei einem Konflikt (`409`) wird der Eintrag nicht überschrieben.

### Request Body

```json
{
    "transactionId": "txn_partner_001",  // optional, muss mit der URL übereinstimmen
    "type": "deposit",                    // "deposit" | "withdraw" | "transfer" | "custom"
    "amount": "100.00",                  // positiver Betrag als String
    "timestamp": "2025-10-28T11:58:02Z",
    "senderPublicKey": "BASE64PUB==",
    "receiverPublicKey": "BASE64PUB==",
    "signature": "BASE64SIG==",
    "metadata": {                         // optional, frei definierbar
        "partnerInstance": "bank-a"
    }
}
```

### Validierung

- `transactionId`: optional im Body, muss – falls vorhanden – exakt der URL entsprechen.
- `type`: einer der vier unterstützten Typen.
- `amount`: größer als `0`, zwei Nachkommastellen empfohlen.
- `signature`: wird gegen den rekonstruierten Nachrichten-Hash verifiziert (`type`, `sender`, `receiver`, `amount`, `timestamp`).
- `metadata`: freies Objekt, wird unverändert persistiert.

### Antworten (POST /api/transactions/{transactionId})

- `201 Created`: Transaktion wurde gespeichert. Antwort enthält den persistierten Ledger-Eintrag.

```json
{
    "transactionId": "txn_partner_001",
    "ledgerEntry": {
        "transactionId": "txn_partner_001",
        "type": "deposit",
        "amount": "100.00",
        "senderPublicKey": "BASE64PUB==",
        "receiverPublicKey": "BASE64PUB==",
        "signature": "BASE64SIG==",
        "timestamp": "2025-10-28T11:58:02Z",
        "metadata": {
            "partnerInstance": "bank-a"
        }
    },
    "storedAt": "2025-10-28T12:00:06.789012+00:00"
}
```

- `400 Bad Request`: Eingabedaten fehlerhaft oder Signatur ungültig (z. B. `"Signatur ungültig"`, `"timestamp darf nicht leer sein"`).
- `409 Conflict`: Transaktion existiert bereits.

---

## GET `/api/transactions/verify/{transactionId}`

Prüft einen vorhandenen Ledger-Eintrag. Die Signatur wird anhand derselben Regeln wie bei der Annahme quelloffen validiert.

### Antworten (GET /api/transactions/verify/{transactionId})

- `200 OK`: Eintrag gefunden.

```json
{
    "transactionId": "txn_partner_001",
    "verified": true,
    "verifiedAt": "2025-10-28T12:00:07.000000+00:00",
    "ledgerEntry": {
        "transactionId": "txn_partner_001",
        "type": "deposit",
        "amount": "100.00",
        "senderPublicKey": "BASE64PUB==",
        "receiverPublicKey": "BASE64PUB==",
        "signature": "BASE64SIG==",
        "timestamp": "2025-10-28T11:58:02Z"
    }
}
```

Bei fehlenden Pflichtfeldern wird `verified` auf `false` gesetzt und `reason` erläutert.

- `404 Not Found`: Eintrag existiert nicht.
- `503 Service Unavailable`: Ledger-Speicher nicht verfügbar (nur bei Speicherfehlern).

---

## Fehlerbehandlung

Alle Fehlerantworten folgen dem Schema `{ "error": "Nachricht" }`. Nachrichten bleiben deutschsprachig.

Clients sollten insbesondere folgende Fehlermeldungen beachten:

- `"Signatur ungültig"`: kryptografische Prüfung fehlgeschlagen.
- `"Transaktion existiert bereits"`: `transactionId` bereits vergeben.
- `"timestamp darf nicht leer sein"`: Feld zwar vorhanden, aber leer.
- `"Ledger-Speicher nicht verfügbar"`: interner Persistenzlayer nicht erreichbar.

---

## Änderungsschronik

- `2025-10-28`: Endpunkte neu definiert – Authentifizierung entfällt vorerst; neue Discovery- und Export-Antworten; Signaturprüfung obligatorisch.
- `2025-10-29`: Export-Endpunkt in Übersicht, vollständigen Dump und paginierte Ausgabe aufgeteilt.
