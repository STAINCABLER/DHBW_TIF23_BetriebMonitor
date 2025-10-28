# Web3.0 Gesamtfahrplan (11 Phasen)

Dieser Plan fasst alle Entwicklungsschritte der Web3.0-Banking-Demo zusammen. Der ursprüngliche 10-Phasen-Fahrplan wurde um die neue Phase 6 (Admin- & Nutzer-APIs) erweitert und umfasst nun elf Etappen. Jede Phase baut auf stabilen Tests (pytest, eslint) und aktualisierten Dokumentationen auf.

| Phase | Status | Kernziele |
| --- | --- | --- |
| 1. Fundament & Auth | Abgeschlossen | Flask-Grundgerüst, Session-Handling, Registrieren/Anmelden, MemoryStore/Upstash Abstraktion. |
| 2. Konto-Basics | Abgeschlossen | Kontostand, Transaktionshistorie, Advisor-Zuordnung, `/api/accounts/me`. |
| 3. Profil & Self-Service | Abgeschlossen | Profilaktualisierung, IBAN-Validierung, Kontolöschung, konsistente Fehlertexte. |
| 4. Schlüsselmanagement v1 | Abgeschlossen | Generierung & Verschlüsselung von Nutzer-Schlüsselpaaren, sichere Speicherung via `encrypt_private_key`. |
| 5. Signierte Transaktionen | Abgeschlossen | Client-Signaturfluss, Argon2-Lader mit CDN-Fallback, Unlock-Modal & Passwort-Refresh. |
| 6. Nutzer & Admin APIs | In Arbeit | Neue `/api/user/keypair` Endpoints, Admin-Ledgerzugriff (`/api/transactions*`), Marshmallow-Validierung. |
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

## Nächste Schritte (Phase 6)

1. Admin-Token-Konfiguration erweitern: Legacy (`ADMIN_API_TOKEN`) dokumentieren und den kreativen Modus (`mode`, `mode_seed`) samt Token-Distribution erläutern.
2. Frontend-Integrationen für Keypair-Rotation prüfen (optional Modal, Callbacks).
3. Erweiterte Tests für Admin-Flows (Negativfälle, Pagination).
4. Dokumentationspflege fortlaufend (dieses Dokument aktualisieren, API-Spezifikationen ergänzen).

Weitere Phasen werden nach Abschluss von Phase 6 verfeinert und terminiert.
