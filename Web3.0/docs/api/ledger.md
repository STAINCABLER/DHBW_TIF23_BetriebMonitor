# Ledger-Discovery-API (Web3.0)

Die Ledger-Discovery stellt eine Übersicht der bekannten Bankknoten bereit und dient als Grundlage für die interne Föderations-Synchronisation. Schreiboperationen werden aktuell serverseitig automatisch verwaltet; externe Clients erhalten für entsprechende Requests HTTP 405. Die Read-Endpunkte können verwendet werden, um Knoten und lokale Instanzdaten auszulesen.

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

Schreibzugriffe sind deaktiviert. Der Server antwortet mit HTTP 405 und der Fehlermeldung `"Ledger-Instanzen werden automatisch verwaltet"`.

## GET `/api/ledger/instances/{instanceId}`

Liefert Details zu einer Instanz.

### Response 200 (Instance Detail)

```json
{
  "instanceId": "bank-a",
  "baseUrl": "https://bank-a.example",
  "status": "online",
  "lastSeen": "2024-05-04T12:00:00+00:00",
  "metadata": {
    "region": "EU"
  }
}
```

### Fehlerantworten (Instance Detail)

| Status | Grund |
| --- | --- |
| 401 | `X-Ledger-Token` fehlt oder ist ungültig. |
| 404 | Instanz wurde nicht gefunden. |
| 503 | Ledger-API ist deaktiviert. |

## PUT `/api/ledger/instances/{instanceId}`

Schreibzugriffe sind deaktiviert. Der Server antwortet mit HTTP 405 und der Fehlermeldung `"Ledger-Instanzen werden automatisch verwaltet"`.

## POST `/api/ledger/instances/{instanceId}/heartbeat`

Schreibzugriffe sind deaktiviert. Der Server antwortet mit HTTP 405 und der Fehlermeldung `"Ledger-Instanzen werden automatisch verwaltet"`.

## DELETE `/api/ledger/instances/{instanceId}`

Schreibzugriffe sind deaktiviert. Der Server antwortet mit HTTP 405 und der Fehlermeldung `"Ledger-Instanzen werden automatisch verwaltet"`.

## Hinweise

- Die Response kann leer sein, wenn keine Knoten konfiguriert sind.
- Synchronisationen werden durch den Server selbst initiiert (`_perform_ledger_sync_cycle`).
- Für langlebige Einträge sorgt der Server intern für Heartbeats; externe Clients erhalten für Heartbeat-Aufrufe HTTP 405.
- Schreiboperationen (`POST`, `PUT`, `heartbeat`, `DELETE`) sind aktuell deaktiviert und liefern HTTP 405.
