# Ledger-Discovery-API (Web3.0)

Die Ledger-Discovery stellt eine Übersicht der bekannten Bankknoten bereit und erlaubt die Verwaltung eigener Instanzen (Registrierung, Heartbeat, Abfrage). Sie wird von internen Sync-Prozessen genutzt, um Zielknoten inklusive optionaler Tokens zu beziehen.

- **Basis-URLs:**
  - `/api/ledger/nodes`
  - `/api/ledger/instances`
- **Authentifizierung:** Erfordert den Header `X-Ledger-Token` mit dem Wert des serverseitigen `LEDGER_API_TOKEN`. Ohne Token sind die Endpunkte deaktiviert (HTTP 503).
- **Antwortformat:** JSON-basierte Ressourcen.

## GET `/api/ledger/nodes`

Gibt alle derzeit konfigurierten Ledger-Knoten zurück. Jeder Eintrag beschreibt eine adressierbare Basis-URL und optional das dazugehörige Zugriffstoken.

### Response 200 (Ledger Nodes)

```json
{
  "nodes": [
    {
      "baseUrl": "https://bank-a.example",
      "token": "optional-override"
    }
  ]
}
```

- `nodes`: Liste der bekannten Zielknoten. Einträge können aus statischen Konfigurationen (`LEDGER_NODE_ADDRESSES`) oder aus expandierten Sync-Zielen (`LEDGER_SYNC_TARGETS`) stammen.
- `token`: Falls gesetzt, überschreibt dieser Wert das globale `LEDGER_API_TOKEN` für Aufrufe gegen den jeweiligen Knoten.

### Fehlerantworten (Ledger Nodes)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder stimmt nicht mit `LEDGER_API_TOKEN` überein. |
| 503 | Ledger-API ist deaktiviert (kein `LEDGER_API_TOKEN` gesetzt). |

## GET `/api/ledger/instances`

Listet alle lokal registrierten Bankinstanzen (eigene Clusterknoten) auf.

### Response 200 (Instance List)

```json
{
  "instances": [
    {
      "instanceId": "bank-a",
      "baseUrl": "https://bank-a.example",
      "status": "online",
      "lastSeen": "2024-05-04T12:00:00+00:00",
      "metadata": {
        "region": "EU"
      }
    }
  ]
}
```

### Fehlerantworten (Instance List)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 503 | Ledger-API ist deaktiviert. |

## POST `/api/ledger/instances`

Registriert eine neue Instanz. `instanceId` muss eindeutig sein.

### Request-JSON (Instance Register)

```json
{
  "instanceId": "bank-a",
  "baseUrl": "https://bank-a.example",
  "publicKey": "PUBKEY",
  "metadata": {
    "region": "EU"
  }
}
```

### Response 201 (Instance Register)

Gibt den gespeicherten Datensatz mit `instanceId` und normalisierter `baseUrl` zurück.

### Fehlerantworten (Instance Register)

| Status | Grund |
| --- | --- |
| 400 | Ungültige Eingaben (z. B. fehlende URL). |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 409 | Instanz existiert bereits. |
| 503 | Ledger-API ist deaktiviert. |

## GET `/api/ledger/instances/{instanceId}`

Liefert Details zu einer Instanz.

### Fehlerantworten (Instance Detail)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 404 | Instanz wurde nicht gefunden. |
| 503 | Ledger-API ist deaktiviert. |

## PUT `/api/ledger/instances/{instanceId}`

Erstellt oder aktualisiert eine Instanz. Ohne vorheriges `POST` kann `PUT` ein neues Objekt erzeugen.

- `baseUrl` wird automatisch normalisiert (fehlendes Schema ⇒ `https://`).
- `metadata`, `status`, `token` und `publicKey` können optional gesetzt werden.
- `lastSeen` wird standardmäßig auf den aktuellen Zeitpunkt gelegt.
- Für neue Instanzen ist `baseUrl` zwingend erforderlich.

### Fehlerantworten (Instance Upsert)

| Status | Grund |
| --- | --- |
| 400 | Ungültige Eingaben. |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 404 | Instanz nicht gefunden (`PUT` mit `require_existing` nicht erfüllt). |
| 503 | Ledger-API ist deaktiviert. |

## POST `/api/ledger/instances/{instanceId}/heartbeat`

Aktualisiert den `lastSeen`-Zeitstempel und optional den Status einer bestehenden Instanz.

### Request-JSON (Heartbeat)

```json
{
  "status": "online",
  "metadata": {
    "load": 0.42
  }
}
```

### Fehlerantworten (Heartbeat)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 404 | Instanz unbekannt. |
| 503 | Ledger-API ist deaktiviert. |

## DELETE `/api/ledger/instances/{instanceId}`

Entfernt eine Instanz aus dem lokalen Register.

### Fehlerantworten (Instance Delete)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 503 | Ledger-API ist deaktiviert. |

## Hinweise

- Die Response kann leer sein, wenn keine Knoten konfiguriert sind.
- Synchronisationen werden durch den Server selbst initiiert (`_perform_ledger_sync_cycle`).
- Für langlebige Einträge sollten Instanzen regelmäßig Heartbeats senden, damit sie in der Liste bleiben.
