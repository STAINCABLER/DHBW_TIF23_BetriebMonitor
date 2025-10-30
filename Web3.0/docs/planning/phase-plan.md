# Web3.0 Gesamtfahrplan (11 Phasen)

Dieser Plan fasst alle Entwicklungsschritte der Web3.0-Banking-Demo zusammen. Der ursprüngliche 10-Phasen-Fahrplan wurde um die neue Phase 6 (Admin- & Nutzer-APIs) erweitert und umfasst nun elf Etappen. Jede Phase baut auf stabilen Tests (pytest, eslint) und aktualisierten Dokumentationen auf.

| Phase | Status | Kernziele |
| --- | --- | --- |
| 1. Fundament & Auth | Abgeschlossen | Flask-Grundgerüst, Session-Handling, Registrieren/Anmelden, MemoryStore/Upstash Abstraktion. |
| 2. Konto-Basics | Abgeschlossen | Kontostand, Transaktionshistorie, Advisor-Zuordnung, `/api/accounts/me`. |
| 3. Profil & Self-Service | Abgeschlossen | Profilaktualisierung, IBAN-Validierung, Kontolöschung, konsistente Fehlertexte. |
| 4. Schlüsselmanagement v1 | Abgeschlossen | Generierung & Verschlüsselung von Nutzer-Schlüsselpaaren, sichere Speicherung via `encrypt_private_key`. |
| 5. Signierte Transaktionen | Abgeschlossen | Client-Signaturfluss, Argon2-Lader mit CDN-Fallback, Unlock-Modal & Passwort-Refresh. |
| 6. Nutzer & Admin APIs | In Arbeit | `/api/user/keypair`, modularisierte Blueprints, Admin-Ledgerzugriff (`/api/transactions*`), Marshmallow-Validierung. |
| 7. Ledger Replikation | Offen | Konsistente Replikationsmechanismen, Delta-Sync, Konflikterkennung. |
| 8. Föderation & Partnerbanken | Offen | Föderierte Kommunikation, Bank-Instanz-Registrierung, Sync-State APIs. |
| 9. Observability | Offen | strukturiertes Logging, Metrics, Alarme (Prometheus/OpenTelemetry TBD). |
| 10. Sicherheit & Hardening | Offen | Rate-Limits, Audit-Trails, Secrets-Management, Security-Reviews. |
| 11. Deployment & Ops | Offen | CI/CD-Erweiterung, Container-Härtung, Betriebshandbuch, Disaster-Recovery-Pläne. |

## Leitplanken für alle Phasen

- **Tests first:** Jede Phase ergänzt oder aktualisiert pytest- und Lint-Coverage.
- **Dokumentationspflicht:** Änderungen an APIs → `docs/api/`; Architektur- oder Roadmap-Updates → `docs/planning/`.
- **Store-Kompatibilität:** Neue Features funktionieren mit `MemoryStore` *und* `UpstashStore`.
- **Internationalisierung:** Fehlermeldungen bleiben deutschsprachig und prägnant.
- **Sicherheitsmodell:** Keine privaten Schlüssel im Klartext speichern; sensible Aktionen erfordern Passwort- oder Token-Bezug.

## Aktueller Stand Phase 6

- API wurde in dedizierte Blueprints (`libaries/api/`) aufgeteilt; `server.py` delegiert über `register_apis`.
- Start- und Build-Workflow ist über `start.sh` sowie die aktualisierte Dockerfile automatisiert (venv + npm Install).
- Ledger- und Konto-Endpunkte nutzen Marshmallow-Schemas; pytest-Suite deckt neue Flows vollständig ab.
- Dokumentation der Auth-, Konto-, Transaktions- und Ledger-Endpunkte wurde aktualisiert (inkl. IBAN-Format, Token-Anforderungen).

## Nächste Schritte (Phase 6)

1. Admin-Token-Konfiguration und kreative Modi (`ADMIN_API_TOKEN`, `mode`, `mode_seed`) detailliert dokumentieren und im UI surface'n.
2. Frontend-Workflows für Schlüsselrotation und Ledger-Verwaltung auf UX-Lücken testen (z. B. modale Bestätigungen, Fehlermeldungen).
3. Negative Tests erweitern (z. B. Manipulationen an Ledger-POSTs, Rate-Limit-Simulationen) und Monitoring-Hooks vorbereiten.
4. Föderations-spezifische Dokumentation vorbereiten (erstes Draft für Phase 7), damit spätere Sync-Implementierungen definiert sind.

Weitere Phasen werden nach Abschluss von Phase 6 verfeinert und terminiert.
