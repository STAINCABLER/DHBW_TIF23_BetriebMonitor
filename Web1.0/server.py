"""Minimaler Python-Webserver zum Ausliefern des Verzeichnisses Web1.0

Starten: python server.py
Öffnen: http://localhost:8000
"""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

# Set the web directory to the directory containing this script
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

if __name__ == '__main__':
    port = 8000
    server = HTTPServer(('0.0.0.0', port), Handler)
    print(f"Starte Webserver auf http://localhost:{port} (Dokumente: {WEB_DIR})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nBeende Server')
        server.server_close()