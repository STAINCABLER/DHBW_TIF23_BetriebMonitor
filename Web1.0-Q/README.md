# Web1.0-Q Nostalgic Banking Login

## Überblick

Diese Demo erweitert die statische Web1.0-Bankseite um erste Web-2.0-Elemente. Ein kleines Flask-Backend rendert dynamische HTML-Templates für Login und Kontoübersicht. Dadurch lässt sich nachvollziehen, wie sich Interaktivität und Personalisierung auf Architektur und Monitoring-Anforderungen auswirken.

## Web-Kontext: Übergang von Web 1.0 zu Web 2.0

- **Serverseitiges Rendering:** HTML-Seiten werden zur Laufzeit mit Nutzerdaten (Name, Kontostand, Zeitstempel) befüllt.
- **Formulare mit Verarbeitung:** Login-Formular wird an den Server gesendet; ein einfacher Credential-Check demonstriert Session-orientierte Abläufe.
- **Template-Wiederverwendung:** `account.html` und `login.html` zeigen, wie Layouts modular gepflegt werden können.
- **Monitoring-Relevanz:** Neben Verfügbarkeit rücken Response-Zeiten, Fehlerraten und Formular-Validierungen in den Fokus. Logs enthalten nun potenziell sensible Daten und müssen bewusst behandelt werden.

## Lernziele & Besonderheiten

- Unterschiede zwischen rein statischen Seiten und serverseitigen Web-Apps erkennen
- Einblick in typische Flask-Strukturen (Routing, Templates, Request Handling)
- Diskussionsgrundlage für Monitoring von Authentifizierungsstrecken (z. B. Login-Failure-Rate, Audit-Logs)

## Projektstruktur

- `app.py` – Flask-Applikation mit Routen für Login und Kontoansicht
- `templates/login.html` – Formularseite im Vintage-Look
- `templates/account.html` – Dynamisch befüllte Kontoübersicht

## Anwendung starten

```powershell
cd Web1.0-Q
python app.py
```

- Browser öffnen und `http://localhost:8000/` aufrufen
- Demo-Zugang: Benutzername `demo`, Passwort `demo123`
- Zum Beenden `Strg + C` im Terminal drücken

> Hinweis: Die Anwendung dient ausschließlich Lernzwecken und verwendet bewusst einfache Sicherheitsmechanismen.
