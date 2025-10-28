# ---- Basis-Image ----
FROM python:3.11-slim

# ---- Metadaten ----
LABEL org.opencontainers.image.description "DHBW TIF23 BetriebMonitor Web3.0"

# ---- Umgebungsvariablen ----
ENV PYTHONUNBUFFERED=1

# ---- Arbeitsverzeichnis ----
WORKDIR /app

# ---- Abhängigkeiten ----
# Install system dependencies required for cryptography build (if any)
# hadolint ignore=DL3008
# Keeping packages unpinned ensures regular security fixes via base image updates
RUN apt-get update \
	&& apt-get install -y --no-install-recommends build-essential libffi-dev \
	&& rm -rf /var/lib/apt/lists/*

# ---- Python-Abhängigkeiten ----
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ---- Anwendung kopieren ----
COPY . /app

# ---- Port freigeben ----
EXPOSE 8000

# ---- Startbefehl ----
CMD ["python", "server.py"]