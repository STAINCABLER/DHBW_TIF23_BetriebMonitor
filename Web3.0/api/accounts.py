"""Kontobezogene API-Endpunkte."""

from decimal import Decimal
from typing import Any

from flask import Blueprint, jsonify, request

bp = Blueprint("accounts", __name__)


def register(app, ctx) -> None:
    """Registriert alle Konto-Routen."""
    store = ctx.store
    error = ctx.error
    require_auth = ctx.require_auth
    clean_name = ctx.clean_name
    clean_email = ctx.clean_email
    clean_iban = ctx.clean_iban
    parse_amount = ctx.parse_amount
    pick_random_advisor = ctx.pick_random_advisor
    get_advisor_by_id = ctx.get_advisor_by_id
    get_user_key_material = ctx.get_user_key_material
    set_user_field = getattr(store, "set_user_field", None)
    format_amount = ctx.format_amount
    verify_transaction_signature = ctx.verify_transaction_signature
    persist_transaction = ctx.persist_transaction
    record_account_transaction = ctx.record_account_transaction
    generate_transaction_id = ctx.generate_transaction_id
    bank_public_key = ctx.bank_public_key

    @bp.get("/api/accounts/me")
    def account_me() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        user = store.get_user(username)
        if not user:
            return error("Benutzer nicht gefunden", 404)

        txns = store.get_transactions(username)
        advisor_id = user.get("advisor_id")
        if not advisor_id:
            advisor_profile = pick_random_advisor()
            try:
                if callable(set_user_field):
                    set_user_field(username, "advisor_id", advisor_profile["id"])
            except Exception:  # pragma: no cover - best effort
                pass
        else:
            advisor_profile = get_advisor_by_id(str(advisor_id))
        key_material = get_user_key_material(username)
        return jsonify(
            {
                "accountId": username,
                "email": user.get("email"),
                "firstName": user.get("first_name"),
                "lastName": user.get("last_name"),
                "iban": user.get("iban"),
                "balance": user.get("balance", "0.00"),
                "transactions": txns,
                "advisor": advisor_profile,
                "publicKey": key_material.get("publicKey") if key_material else None,
                "keyCreatedAt": key_material.get("createdAt") if key_material else None,
                "encryptedPrivateKey": key_material.get("encryptedPrivateKey") if key_material else None,
                "bankPublicKey": bank_public_key,
            }
        )

    @bp.put("/api/accounts/me")
    def account_update() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            first_name = clean_name(payload.get("firstName"), "Vorname")
            last_name = clean_name(payload.get("lastName"), "Nachname")
            email = clean_email(payload.get("email"))
        except ValueError as exc:
            return error(str(exc))

        updater = getattr(store, "update_user_profile", None)
        if not callable(updater):  # pragma: no cover - alle Stores sollten dies unterstützen
            return error("Profilaktualisierung derzeit nicht möglich", 500)

        try:
            updater(
                username,
                first_name=first_name,
                last_name=last_name,
                email=email,
            )
        except KeyError:
            return error("Benutzer nicht gefunden", 404)
        except ValueError as exc:
            message = str(exc)
            status = 409 if "existiert" in message else 400
            return error(message, status)

        return jsonify({"success": True})

    @bp.delete("/api/accounts/me")
    def account_delete() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            confirm_iban = clean_iban(payload.get("confirmIban"))
        except ValueError as exc:
            return error(str(exc))

        user = store.get_user(username)
        if not user:
            return error("Benutzer nicht gefunden", 404)

        stored_iban = str(user.get("iban") or "").replace(" ", "").upper()
        if not stored_iban:
            return error("IBAN fehlt für dieses Konto", 400)
        if confirm_iban != stored_iban:
            return error("IBAN stimmt nicht überein", 400)

        deleter = getattr(store, "delete_user", None)
        if deleter is None:
            return error("Kontolöschung derzeit nicht möglich", 500)

        try:
            deleter(username)
        except KeyError as exc:
            return error(str(exc), 404)

        token = request.environ.get("session_token")
        if token:
            store.delete_session(token)

        ctx.delete_user_key_material(username)

        return jsonify({"success": True})

    @bp.post("/api/accounts/deposit")
    def account_deposit() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            amount = parse_amount(payload.get("amount"))
            if amount <= Decimal("0"):
                raise ValueError("Betrag muss positiv sein")
        except ValueError as exc:
            return error(str(exc))

        timestamp_raw = payload.get("timestamp")
        if not isinstance(timestamp_raw, str) or not timestamp_raw.strip():
            return error("Zeitstempel fehlt")
        timestamp = timestamp_raw.strip()

        signature_raw = payload.get("signature")
        if not isinstance(signature_raw, str) or not signature_raw.strip():
            return error("Signatur fehlt")
        signature = signature_raw.strip()

        key_material = get_user_key_material(username)
        if not key_material:
            return error("Schlüsselmaterial nicht gefunden", 500)

        sender_public_key = key_material.get("publicKey")
        receiver_public_key = sender_public_key
        amount_str = format_amount(amount.copy_abs())

        if not verify_transaction_signature(
            "deposit",
            sender_public_key,
            receiver_public_key,
            amount_str,
            timestamp,
            signature,
        ):
            return error("Signatur ungültig", 400)

        try:
            balance = store.adjust_balance(username, amount)
        except (KeyError, ValueError) as exc:
            return error(str(exc), 400)

        transaction_id = persist_transaction(
            username=username,
            txn_type="deposit",
            amount=amount,
            balance=balance,
            memo="Einzahlung",
            sender_public_key=sender_public_key,
            receiver_public_key=receiver_public_key,
            signature=signature,
            timestamp=timestamp,
        )
        return jsonify({"balance": format_amount(balance), "transactionId": transaction_id})

    @bp.post("/api/accounts/withdraw")
    def account_withdraw() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            amount = parse_amount(payload.get("amount"))
            if amount <= Decimal("0"):
                raise ValueError("Betrag muss positiv sein")
        except ValueError as exc:
            return error(str(exc))

        timestamp_raw = payload.get("timestamp")
        if not isinstance(timestamp_raw, str) or not timestamp_raw.strip():
            return error("Zeitstempel fehlt")
        timestamp = timestamp_raw.strip()

        signature_raw = payload.get("signature")
        if not isinstance(signature_raw, str) or not signature_raw.strip():
            return error("Signatur fehlt")
        signature = signature_raw.strip()

        key_material = get_user_key_material(username)
        if not key_material:
            return error("Schlüsselmaterial nicht gefunden", 500)

        sender_public_key = key_material.get("publicKey")
        receiver_public_key = bank_public_key
        amount_str = format_amount(amount.copy_abs())

        if not verify_transaction_signature(
            "withdraw",
            sender_public_key,
            receiver_public_key,
            amount_str,
            timestamp,
            signature,
        ):
            return error("Signatur ungültig", 400)

        try:
            balance = store.adjust_balance(username, -amount)
        except ValueError as exc:
            return error(str(exc), 400)
        except KeyError as exc:
            return error(str(exc), 404)

        transaction_id = persist_transaction(
            username=username,
            txn_type="withdraw",
            amount=-amount,
            ledger_amount=amount,
            balance=balance,
            memo="Auszahlung",
            sender_public_key=sender_public_key,
            receiver_public_key=receiver_public_key,
            signature=signature,
            timestamp=timestamp,
        )
        return jsonify({"balance": format_amount(balance), "transactionId": transaction_id})

    @bp.post("/api/accounts/transfer")
    def account_transfer() -> Any:
        try:
            username = require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            target_iban = clean_iban(payload.get("targetIban"))
            target_first = clean_name(payload.get("targetFirstName"), "Empfänger-Vorname")
            target_last = clean_name(payload.get("targetLastName"), "Empfänger-Nachname")
            amount = parse_amount(payload.get("amount"))
            if amount <= Decimal("0"):
                raise ValueError("Betrag muss positiv sein")
        except ValueError as exc:
            return error(str(exc))

        timestamp_raw = payload.get("timestamp")
        if not isinstance(timestamp_raw, str) or not timestamp_raw.strip():
            return error("Zeitstempel fehlt")
        timestamp = timestamp_raw.strip()

        signature_raw = payload.get("signature")
        if not isinstance(signature_raw, str) or not signature_raw.strip():
            return error("Signatur fehlt")
        signature = signature_raw.strip()

        source_user = store.get_user(username)
        if not source_user:
            return error("Benutzer nicht gefunden", 404)

        key_material = get_user_key_material(username)
        if not key_material:
            return error("Schlüsselmaterial nicht gefunden", 500)
        sender_public_key = key_material.get("publicKey")

        resolve_by_iban = getattr(store, "get_user_by_iban", None)
        if resolve_by_iban is None:
            return error("Überweisungen sind derzeit nicht möglich", 500)

        target_user = resolve_by_iban(target_iban)
        if not target_user:
            return error("Zielkonto existiert nicht", 404)

        target_username = target_user.get("username")
        if not target_username:
            return error("Zielkonto konnte nicht geladen werden", 500)

        if target_username == username:
            return error("Zielkonto muss abweichen")

        stored_first = (target_user.get("first_name") or "").strip().casefold()
        stored_last = (target_user.get("last_name") or "").strip().casefold()
        stored_iban = (target_user.get("iban") or "").replace(" ", "").upper()
        if stored_iban != target_iban:
            return error("IBAN konnte nicht bestätigt werden")
        if stored_first != target_first.casefold() or stored_last != target_last.casefold():
            return error("Empfängerdaten stimmen nicht mit der IBAN überein")

        target_key_material = get_user_key_material(target_username)
        if not target_key_material:
            return error("Empfänger besitzt kein Schlüsselmaterial", 500)

        receiver_public_key = target_key_material.get("publicKey")
        amount_str = format_amount(amount.copy_abs())

        if not verify_transaction_signature(
            "transfer",
            sender_public_key,
            receiver_public_key,
            amount_str,
            timestamp,
            signature,
        ):
            return error("Signatur ungültig", 400)

        try:
            source_balance = store.adjust_balance(username, -amount)
        except ValueError as exc:
            return error(str(exc), 400)
        except KeyError as exc:
            return error(str(exc), 404)

        target_balance = store.adjust_balance(target_username, amount)

        source_first = (source_user.get("first_name") or "").strip()
        source_last = (source_user.get("last_name") or "").strip()
        source_iban = (source_user.get("iban") or "").strip()

        transaction_id = generate_transaction_id()

        persist_transaction(
            username=username,
            txn_type="transfer_out",
            amount=-amount,
            ledger_amount=amount,
            balance=source_balance,
            memo=f"Überweisung an {target_first} {target_last}",
            sender_public_key=sender_public_key,
            receiver_public_key=receiver_public_key,
            signature=signature,
            timestamp=timestamp,
            transaction_id=transaction_id,
            extra={
                "counterpartyIban": target_iban,
                "counterpartyName": f"{target_first} {target_last}".strip(),
                "counterpartyPublicKey": receiver_public_key,
            },
        )
        record_account_transaction(
            target_username,
            "transfer_in",
            amount,
            target_balance,
            f"Überweisung von {source_first} {source_last}",
            transaction_id=transaction_id,
            sender_public_key=sender_public_key,
            receiver_public_key=receiver_public_key,
            signature=signature,
            timestamp=timestamp,
            extra={
                "counterpartyIban": source_iban,
                "counterpartyName": f"{source_first} {source_last}".strip(),
                "counterpartyPublicKey": sender_public_key,
            },
        )

        return jsonify({"balance": format_amount(source_balance), "transactionId": transaction_id})

    @bp.post("/api/accounts/resolve")
    def account_resolve() -> Any:
        try:
            require_auth()
        except PermissionError as exc:
            return error(str(exc), 401)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            target_iban = clean_iban(payload.get("targetIban"))
        except ValueError as exc:
            return error(str(exc))

        resolve_by_iban = getattr(store, "get_user_by_iban", None)
        if resolve_by_iban is None:
            return error("Auflösung nicht verfügbar", 500)

        target_user = resolve_by_iban(target_iban)
        if not target_user:
            return error("Konto nicht gefunden", 404)

        username = target_user.get("username")
        if not username:
            return error("Konto beschädigt", 500)

        key_material = get_user_key_material(username)
        return jsonify(
            {
                "accountId": username,
                "firstName": target_user.get("first_name"),
                "lastName": target_user.get("last_name"),
                "publicKey": key_material.get("publicKey") if key_material else None,
                "keyCreatedAt": key_material.get("createdAt") if key_material else None,
            }
        )

    app.register_blueprint(bp)
