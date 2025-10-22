from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Hardcoded demo credentials
    if username == "demo" and password == "demo123":
        return render_template(
            "account.html",
            name="Max Mustermann",
            balance="4.321,45 EUR",
            timestamp=datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        )
    else:
        return """<html><body bgcolor="#fff0f0" text="#000000">
        <center><h2>❌ Login fehlgeschlagen</h2>
        <p>Benutzername oder Passwort sind ungültig.</p>
        <a href="/">Zurück zum Login</a></center></body></html>"""

if __name__ == "__main__":
    app.run(port=8000, debug=True)
