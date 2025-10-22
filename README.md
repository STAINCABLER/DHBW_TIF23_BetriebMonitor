# DHBW_TIF23_BetriebMonitor

## Deutsche Volksbank - Web 1.0 Static Website

Eine statische Bank-Website im klassischen Web 1.0 Stil ohne interaktive Elemente.

### Beschreibung

Dieses Projekt enthält eine rein statische Webseite für eine fiktive Bank (Deutsche Volksbank) im nostalgischen Web 1.0 Design. Die Webseite verwendet klassische HTML/CSS-Elemente und wird über einen einfachen Python HTTP-Server bereitgestellt.

### Features

- **Rein statische Inhalte** - Keine JavaScript-Interaktionen
- **Klassisches Web 1.0 Design** - Nostalgisches Layout mit klassischen Farben und Elementen
- **Bank-Inhalte**:
  - Konten-Angebote (Girokonto, Sparkonto, Tagesgeldkonto)
  - Services (Überweisungen, Daueraufträge, Depotführung)
  - Kredit-Angebote (Privatkredit, Immobilienkredit, Autokredit)
  - Kontaktinformationen
- **Python Webserver** - Einfacher HTTP-Server zum Bereitstellen der statischen Dateien

### Anforderungen

- Python 3.x

### Installation und Ausführung

1. Repository klonen oder herunterladen
2. In das Projektverzeichnis wechseln:
   ```bash
   cd DHBW_TIF23_BetriebMonitor
   ```

3. Den Webserver starten:
   ```bash
   python3 server.py
   ```

4. Die Website im Browser öffnen:
   ```
   http://localhost:8000
   ```

5. Server stoppen mit `Ctrl+C`

### Projektstruktur

```
DHBW_TIF23_BetriebMonitor/
├── server.py           # Python HTTP-Server
├── web/
│   ├── index.html     # Hauptseite mit Bank-Inhalten
│   └── style.css      # Web 1.0 Styling
└── README.md          # Diese Datei
```

### Web 1.0 Design-Elemente

- Klassische HTML-Tabellen für Layout
- Einfache Navigation mit Text-Links
- Klassische Farbschemata (Blau, Gelb, Grau)
- Visitor Counter im Footer
- "Optimiert für Netscape Navigator" Hinweis
- Keine JavaScript-Funktionalität
- Statische Inhalte ohne Interaktionen