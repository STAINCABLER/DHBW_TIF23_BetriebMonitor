# ---- Basis-Image ----
FROM python:3.11-slim

# ---- Metadaten ----
LABEL org.opencontainers.image.description "DHBW TIF23 BetriebMonitor Web1.0"

# ---- Arbeitsverzeichnis ----
WORKDIR /app

# ---- Dateien kopieren ----
COPY . /app

# ---- Port freigeben ----
EXPOSE 8000

# ---- Startbefehl ----
CMD ["python", "server.py"]