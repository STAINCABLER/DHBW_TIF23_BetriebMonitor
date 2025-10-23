# ---- Basis-Image ----
FROM python:3.11-slim

# ---- Arbeitsverzeichnis ----
WORKDIR /app

# ---- Dateien kopieren ----
COPY . /app

# ---- Port freigeben ----
EXPOSE 8000

# ---- Startbefehl ----
CMD ["python", "server.py"]