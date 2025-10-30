"""API-Endpunkte für Nutzer-Schlüsselmaterial."""

import base64
from typing import Any, Dict

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

bp = Blueprint("user", __name__)


def register(app, ctx) -> None:
    """Registriert alle Schlüsselverwaltungs-Routen."""
    store = ctx.store
    error = ctx.error
    require_auth = ctx.require_auth
    keypair_rotate_schema = ctx.keypair_rotate_schema
    keypair_delete_schema = ctx.keypair_delete_schema
    verify_password = ctx.verify_password
    get_user_key_material = ctx.get_user_key_material
    set_user_key_material = ctx.set_user_key_material
    delete_user_key_material = ctx.delete_user_key_material
    generate_user_keypair = ctx.generate_user_keypair
    encrypt_private_key = ctx.encrypt_private_key
    user_key_pepper = ctx.user_key_pepper
    now_iso = ctx.now_iso
    validation_error_message = ctx.validation_error_message

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
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            data = keypair_rotate_schema.load(payload)
        except ValidationError as exc:
            return error(validation_error_message(exc))

        user = store.get_user(username)
        if not user:
            return error("Benutzer nicht gefunden", 404)
        if not verify_password(data["password"], user):
            return error("Passwort ist falsch", 400)

        previous_material = get_user_key_material(username)

        keypair = generate_user_keypair()
        encrypted = encrypt_private_key(
            data["password"],
            keypair.private_key,
            pepper=user_key_pepper,
        )
        created_at = now_iso()
        set_user_key_material(
            username,
            public_key=keypair.public_key_b64(),
            encrypted_private_key=encrypted,
            created_at=created_at,
        )

        response_body: Dict[str, Any] = {
            "publicKey": keypair.public_key_b64(),
            "encryptedPrivateKey": encrypted,
            "createdAt": created_at,
        }
        if previous_material and previous_material.get("publicKey"):
            response_body["previousPublicKey"] = previous_material.get("publicKey")
        if data.get("expose_private_key"):
            response_body["privateKey"] = base64.b64encode(keypair.private_key).decode("ascii")

        return jsonify(response_body), 201

    @bp.delete("/api/user/keypair")
    def user_keypair_delete() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            data = keypair_delete_schema.load(payload)
        except ValidationError as exc:
            return error(validation_error_message(exc))

        user = store.get_user(username)
        if not user:
            return error("Benutzer nicht gefunden", 404)
        if not verify_password(data["password"], user):
            return error("Passwort ist falsch", 400)

        material = get_user_key_material(username)
        if not material:
            return error("Schlüsselmaterial nicht gefunden", 404)

        delete_user_key_material(username)

        return jsonify({
            "success": True,
            "revokedPublicKey": material.get("publicKey"),
        })

    app.register_blueprint(bp)
