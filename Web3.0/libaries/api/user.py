"""API-Endpunkte für Nutzer-Schlüsselmaterial."""

import base64
import binascii
from typing import Any

from flask import Blueprint, jsonify

bp = Blueprint("user", __name__)


def register(app, ctx) -> None:
    """Registriert alle Schlüsselverwaltungs-Routen."""
    error = ctx.error
    require_auth = ctx.require_auth
    get_user_key_material = ctx.get_user_key_material
    require_ledger_token = ctx.require_ledger_token
    ledger_error_response = ctx.ledger_error_response
    store = ctx.store
    bank_name = ctx.bank_name

    @bp.get("/api/user/keypair")
    def user_keypair_get() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        material = get_user_key_material(username)
        if not material:
            return error("Schlüsselmaterial nicht gefunden", 404)

        return jsonify(
            {
                "publicKey": material.get("publicKey"),
                "createdAt": material.get("createdAt"),
                "encryptedPrivateKey": material.get("encryptedPrivateKey"),
            }
        )

    @bp.post("/api/user/keypair")
    def user_keypair_rotate() -> Any:
        try:
            require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)
        return error("Schlüsselwechsel ist deaktiviert", 405)

    @bp.delete("/api/user/keypair")
    def user_keypair_delete() -> Any:
        try:
            require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)
        return error("Schlüsselwiderruf ist deaktiviert", 405)

    @bp.get("/api/user/data/<path:public_key_b64>")
    def user_public_data(public_key_b64: str) -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)

        normalized = str(public_key_b64 or "").strip()
        if not normalized:
            return error("Öffentlicher Schlüssel fehlt")

        try:
            base64.b64decode(normalized, validate=True)
        except binascii.Error:
            return error("Öffentlicher Schlüssel ungültig")

        resolver = getattr(store, "get_user_by_public_key", None)
        if not callable(resolver):
            return error("Abfrage nicht verfügbar", 503)

        user = resolver(normalized)
        if not user:
            return error("Benutzer nicht gefunden", 404)

        first_name = user.get("first_name") or user.get("firstName")
        last_name = user.get("last_name") or user.get("lastName")

        return jsonify(
            {
                "iban": user.get("iban"),
                "bankName": bank_name,
                "firstName": first_name,
                "lastName": last_name,
            }
        )

    app.register_blueprint(bp)
