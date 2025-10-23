# Web1.0 Bank Demo

## Überblick

Diese Mini-Webseite simuliert das Online-Banking einer fiktiven Bank und bildet typische Merkmale früher Web-1.0-Angebote ab. Der Fokus liegt auf statischen HTML-Seiten, tabellenbasiertem Layout und minimalistischer Navigation.

## Web-Kontext: Warum Web 1.0?

- **Statische Auslieferung:** Alle Seiten werden als unveränderte HTML-Dokumente ausgeliefert, ohne serverseitige Logik oder Client-Scripting.
- **Layout durch Tabellen & Inline-Styling:** Gestaltung erfolgt überwiegend über HTML-Attribute statt moderne CSS-Techniken.
- **Lineare Nutzerführung:** Es gibt kaum Interaktion oder Personalisierung; Inhalte werden rein konsumiert.
- **Monitoring-Relevanz:** Web 1.0 beschränkt sich meist auf grundlegende Verfügbarkeits-Checks (HTTP-Status, Uptime) und rudimentäre Log-Analyse, da keine komplexen Nutzerflüsse vorliegen.

## Lernziele & Besonderheiten

- Einblick in Aufbau und Einschränkungen früher Webangebote
- Vergleichsbasis für spätere Web 2.0/3.0 Implementierungen im Projekt
- Grundlage für Diskussionen zu Monitoring-Metriken (z. B. Response-Zeiten vs. Nutzeraktionen)

## Projektstruktur

- `index.html` – Startseite im Web-1.0-Stil
- `login.html` – Statisches Formular ohne serverseitige Verarbeitung
- `assets/` – Bilder und statische Ressourcen
- `css/styles.css` – Schlankes Stylesheet für grundlegende Formatierungen
- `server.py` – Minimaler Entwicklungsserver auf Basis von Python `http.server`

## Anwendung starten

```powershell
cd Web1.0
python server.py
```

- Browser öffnen und `http://localhost:8000/` aufrufen
- Zum Beenden `Strg + C` im Terminal drücken

> Hinweis: Der Server ist rein für lokale Demonstrationszwecke gedacht und besitzt keine produktiven Sicherheitsmechanismen.
