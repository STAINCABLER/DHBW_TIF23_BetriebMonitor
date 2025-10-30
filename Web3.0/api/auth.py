"""Authentifizierungs- und Benutzer-Setup-Endpunkte."""

from decimal import Decimal
from typing import Any

from flask import Blueprint, jsonify, request

bp = Blueprint("auth", __name__)


def register(app, ctx) -> None:
    """Registriert Authentifizierungsrouten."""
    store = ctx.store
    error = ctx.error
    clean_email = ctx.clean_email
    clean_password = ctx.clean_password
    clean_name = ctx.clean_name
    parse_amount = ctx.parse_amount
    hash_password = ctx.hash_password
    generate_account_id = ctx.generate_account_id
    generate_iban = ctx.generate_iban
    pick_random_advisor = ctx.pick_random_advisor
    issue_user_keypair = ctx.issue_user_keypair
    persist_transaction = ctx.persist_transaction
    format_amount = ctx.format_amount
    now_iso = ctx.now_iso
    get_user_key_material = ctx.get_user_key_material
    ensure_user_key_material = ctx.ensure_user_key_material
    verify_password = ctx.verify_password
    issue_session = ctx.issue_session
    user_key_pepper = ctx.user_key_pepper
    decrypt_private_key = ctx.decrypt_private_key
    encrypt_private_key = ctx.encrypt_private_key
    sign_message_b64 = ctx.sign_message_b64
    build_transaction_message = ctx.build_transaction_message
    set_user_key_material = ctx.set_user_key_material
    require_auth = ctx.require_auth
    decryption_error = ctx.decryption_error

    @bp.post("/api/auth/register")
    def register_user() -> Any:
        payload = request.get_json(force=True, silent=True) or {}
        try:
            email = clean_email(payload.get("email"))
            password = clean_password(payload.get("password"))
            first_name = clean_name(payload.get("firstName"), "Vorname")
            last_name = clean_name(payload.get("lastName"), "Nachname")
            initial = parse_amount(payload.get("initialDeposit", "0"))
            if initial < Decimal("0"):
                raise ValueError("Initialer Betrag darf nicht negativ sein")
        except ValueError as exc:
            return error(str(exc))

        email_exists = getattr(store, "email_exists", None)
        if email_exists and email_exists(email):
            return error("E-Mail existiert bereits", 409)

        credentials = hash_password(password)
        account_id = generate_account_id()
        iban = generate_iban()
        advisor = pick_random_advisor()
        store.create_user(
            account_id,
            {
                "username": account_id,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "iban": iban,
                "salt": credentials["salt"],
                "password_hash": credentials["password_hash"],
                "balance": format_amount(Decimal("0")),
                "advisor_id": advisor["id"],
            },
        )

        key_material = issue_user_keypair(account_id, password, expose_private=True)
        private_key_bytes = key_material.pop("_privateKeyBytes", None)

        if initial > Decimal("0"):
            sender_public_key = key_material["publicKey"]
            receiver_public_key = sender_public_key
            timestamp = now_iso()
            amount_str = format_amount(initial)
            if private_key_bytes is None:
                try:
                    material = get_user_key_material(account_id)
                    if material:
                        private_key_bytes = decrypt_private_key(
                            password,
                            material["encryptedPrivateKey"],
                            pepper=user_key_pepper,
                        )
                except decryption_error:  # pragma: no cover - fallback auf unsignierte Buchung
                    private_key_bytes = None
            signature = ""
            if private_key_bytes is not None:
                message = build_transaction_message(
                    "deposit",
                    sender_public_key,
                    receiver_public_key,
                    amount_str,
                    timestamp,
                )
                signature = sign_message_b64(private_key_bytes, message)

            new_balance = store.adjust_balance(account_id, initial)
            persist_transaction(
                username=account_id,
                txn_type="deposit",
                amount=initial,
                balance=new_balance,
                memo="Initiale Einzahlung",
                sender_public_key=sender_public_key,
                receiver_public_key=receiver_public_key,
                signature=signature,
                timestamp=timestamp,
            )

        token = issue_session(account_id)
        return jsonify(
            {
                "token": token,
                "firstName": first_name,
                "lastName": last_name,
                "iban": iban,
                "publicKey": key_material["publicKey"],
                "keyCreatedAt": key_material["createdAt"],
                "encryptedPrivateKey": key_material["encryptedPrivateKey"],
                "advisor": advisor,
            }
        )

    @bp.post("/api/auth/login")
    def login() -> Any:
        payload = request.get_json(force=True, silent=True) or {}
        try:
            email = clean_email(payload.get("email"))
            password = clean_password(payload.get("password"))
        except ValueError as exc:
            return error(str(exc))

        user = getattr(store, "get_user_by_email", lambda _: None)(email)
        if not user or not verify_password(password, user):
            return error("Ungültige Zugangsdaten", 401)

        account_id = user.get("username")
        if not account_id:
            return error("Benutzerkonto beschädigt", 500)

        token = issue_session(account_id)
        key_material = ensure_user_key_material(account_id, password)
        return jsonify(
            {
                "token": token,
                "firstName": user.get("first_name"),
                "lastName": user.get("last_name"),
                "iban": user.get("iban"),
                "publicKey": key_material.get("publicKey") if key_material else None,
                "keyCreatedAt": key_material.get("createdAt") if key_material else None,
                "encryptedPrivateKey": key_material.get("encryptedPrivateKey") if key_material else None,
            }
        )

    @bp.post("/api/auth/logout")
    def logout() -> Any:
        try:
            username = require_auth()
            token = request.environ.get("session_token")
            if token:
                store.delete_session(token)
            return jsonify({"success": True, "username": username})
        except PermissionError as exc:
            return error(str(exc), 401)

    @bp.put("/api/auth/password")
    def update_password() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            current_password = clean_password(payload.get("currentPassword"))
            new_password = clean_password(payload.get("newPassword"))
        except ValueError as exc:
            return error(str(exc))

        confirm_password = payload.get("confirmPassword")
        if confirm_password is not None:
            confirm_clean = str(confirm_password).strip()
            if confirm_clean != new_password:
                return error("Neue Passwörter stimmen nicht überein")

        user = store.get_user(username)
        if not user:
            return error("Benutzer nicht gefunden", 404)

        if not verify_password(current_password, user):
            return error("Aktuelles Passwort ist falsch", 400)

        credentials = hash_password(new_password)
        try:
            store.set_user_field(username, "salt", credentials["salt"])
            store.set_user_field(username, "password_hash", credentials["password_hash"])
        except KeyError as exc:
            return error(str(exc), 404)

        key_material = get_user_key_material(username)
        if key_material:
            try:
                private_key_bytes = decrypt_private_key(
                    current_password,
                    key_material["encryptedPrivateKey"],
                    pepper=user_key_pepper,
                )
            except decryption_error:
                return error("Schlüssel konnte nicht entschlüsselt werden", 500)

            new_payload = encrypt_private_key(
                new_password,
                private_key_bytes,
                pepper=user_key_pepper,
            )
            set_user_key_material(
                username,
                public_key=key_material["publicKey"],
                encrypted_private_key=new_payload,
                created_at=now_iso(),
            )
        else:
            ensure_user_key_material(username, new_password)

        return jsonify({"success": True})

    app.register_blueprint(bp)
