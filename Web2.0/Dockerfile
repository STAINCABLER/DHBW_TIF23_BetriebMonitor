# ---- Basis-Image ----
FROM python:3.11-slim

# ---- Umgebungsvariablen ----
ENV PYTHONUNBUFFERED=1

# ---- Arbeitsverzeichnis ----
WORKDIR /app

# ---- Abhängigkeiten ----
RUN pip install --no-cache-dir \
	Flask==3.0.3 \
	python-dotenv==1.0.1 \
	upstash-redis==1.5.0

# ---- Anwendung kopieren ----
COPY . /app

# ---- Port freigeben ----
EXPOSE 8000

# ---- Startbefehl ----
CMD ["python", "server.py"]