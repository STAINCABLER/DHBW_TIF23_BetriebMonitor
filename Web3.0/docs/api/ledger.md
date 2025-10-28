# Ledger-Discovery-API (Web3.0)

Die Ledger-Discovery stellt eine Übersicht der bekannten Bankknoten bereit. Sie wird von internen Sync-Prozessen genutzt, um Zielknoten inklusive optionaler Tokens zu beziehen.

- **Basis-URL:** `/api/ledger/nodes`
- **Authentifizierung:** Erfordert den Header `X-Ledger-Token` mit dem Wert des serverseitigen `LEDGER_API_TOKEN`. Ohne Token sind die Endpunkte deaktiviert (HTTP 503).
- **Antwortformat:** JSON mit einer Liste von Knotenbeschreibungen.

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

## Hinweise

- Die Response kann leer sein, wenn keine Knoten konfiguriert sind.
- Der Endpunkt liefert ausschließlich Metadaten; Synchronisationen werden durch den Server selbst initiiert (`_perform_ledger_sync_cycle`).
