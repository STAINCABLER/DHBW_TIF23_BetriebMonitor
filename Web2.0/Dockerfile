# ---- Basis-Image ----
FROM python:3.11-slim

# ---- Umgebungsvariablen ----
ENV PYTHONUNBUFFERED=1

# ---- Arbeitsverzeichnis ----
WORKDIR /app

# ---- Abhängigkeiten ----
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# ---- Anwendung kopieren ----
COPY . /app

# ---- Port freigeben ----
EXPOSE 8000

# ---- Startbefehl ----
CMD ["python", "server.py"]