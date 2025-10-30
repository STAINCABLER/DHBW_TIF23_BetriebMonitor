# ---- Basis-Image ----
FROM python:3.11-slim

# ---- Metadaten ----
LABEL org.opencontainers.image.description="DHBW TIF23 BetriebMonitor Web3.0"

# ---- Umgebungsvariablen ----
ENV PYTHONUNBUFFERED=1

# ---- Arbeitsverzeichnis ----
WORKDIR /app

# ---- Abhängigkeiten ----
# hadolint ignore=DL3008
RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential libffi-dev nodejs npm \
	&& rm -rf /var/lib/apt/lists/*

# ---- Anwendung kopieren ----
COPY . /app

# ---- Start-Skript vorbereiten ----
RUN chmod +x /app/start.sh

# ---- Port freigeben ----
EXPOSE 8000

# ---- Startbefehl ----
CMD ["bash", "./start.sh"]
