"""Transaktions- und Ledger-Export-Endpunkte."""

from decimal import Decimal
from typing import Any, Dict

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

bp = Blueprint("transactions", __name__)


def register(app, ctx) -> None:
    """Registriert die Transaktions-API."""
    store = ctx.store
    error = ctx.error
    now_iso = ctx.now_iso
    collect_all = ctx.collect_all_ledger_transactions
    paginate = ctx.paginate_ledger_transactions
    incoming_schema = ctx.incoming_transaction_schema
    format_amount = ctx.format_amount
    verify_signature = ctx.verify_transaction_signature

    @bp.get("/api/transactions")
    def transactions_overview() -> Any:
        base_url = request.host_url.rstrip("/")
        endpoints = [
            {
                "method": "GET",
                "path": "/api/transactions",
                "url": f"{base_url}/api/transactions",
                "description": "Listet sämtliche verfügbaren Transaktions-Endpunkte dieser Instanz auf.",
            },
            {
                "method": "GET",
                "path": "/api/transactions/export",
                "url": f"{base_url}/api/transactions/export",
                "description": "Listet verfügbare Export-Varianten (vollständig vs. paginiert).",
            },
            {
                "method": "POST",
                "path": "/api/transactions/{transactionId}",
                "url": f"{base_url}/api/transactions/{{transactionId}}",
                "description": "Empfängt eingehende Transaktionen anderer Institute und legt sie im Ledger ab.",
            },
            {
                "method": "GET",
                "path": "/api/transactions/verify/{transactionId}",
                "url": f"{base_url}/api/transactions/verify/{{transactionId}}",
                "description": "Prüft eine vorhandene Ledger-Transaktion auf Gültigkeit der Signatur.",
            },
        ]
        return jsonify({
            "generatedAt": now_iso(),
            "endpoints": endpoints,
        })

    @bp.get("/api/transactions/export")
    def transactions_export_overview() -> Any:
        base_url = request.host_url.rstrip("/")
        return jsonify(
            {
                "generatedAt": now_iso(),
                "exports": [
                    {
                        "path": "/api/transactions/export/all",
                        "description": "Gibt das vollständige Ledger als einmaligen JSON-Dump zurück.",
                        "url": f"{base_url}/api/transactions/export/all",
                    },
                    {
                        "path": "/api/transactions/export/stream",
                        "description": "Liefert das Ledger paginiert (Parameter: limit, sinceId).",
                        "url": f"{base_url}/api/transactions/export/stream",
                    },
                ],
            }
        )

    @bp.get("/api/transactions/export/all")
    def transactions_export_all() -> Any:
        transactions = collect_all()
        return jsonify(
            {
                "exportedAt": now_iso(),
                "transactions": transactions,
                "count": len(transactions),
            }
        )

    @bp.get("/api/transactions/export/stream")
    def transactions_export_stream() -> Any:
        since_id = request.args.get("sinceId")
        try:
            limit_raw = request.args.get("limit", "200")
            limit = int(limit_raw)
        except ValueError:
            return error("limit muss eine ganze Zahl sein")

        if limit <= 0 or limit > 500:
            return error("limit muss zwischen 1 und 500 liegen")

        result = paginate(since_id=since_id, limit=limit)
        result.update(
            {
                "exportedAt": now_iso(),
                "limit": limit,
                "sinceId": since_id,
            }
        )
        return jsonify(result)

    @bp.post("/api/transactions")
    def transactions_post_root() -> Any:
        return error("Verwende POST /api/transactions/{transactionId} für neue Einträge", 405)

    @bp.post("/api/transactions/<string:transaction_id>")
    def transactions_receive(transaction_id: str) -> Any:
        payload = request.get_json(force=True, silent=True) or {}
        try:
            data = incoming_schema.load(payload)
        except ValidationError as exc:
            return error(ctx.validation_error_message(exc))

        body_transaction_id = data.get("transaction_id")
        if body_transaction_id and body_transaction_id != transaction_id:
            return error("transactionId widerspricht der URL", 400)

        amount = Decimal(str(data["amount"]))
        amount_str = format_amount(amount.copy_abs())
        timestamp = str(data["timestamp"]).strip()
        if not timestamp:
            return error("timestamp darf nicht leer sein")

        signature = str(data["signature"]).strip()
        if not signature:
            return error("Signatur fehlt")

        if not verify_signature(
            str(data["type"]),
            str(data["sender_public_key"]),
            str(data["receiver_public_key"]),
            amount_str,
            timestamp,
            signature,
        ):
            return error("Signatur ungültig", 400)

        ledger_entry: Dict[str, Any] = {
            "transactionId": transaction_id,
            "type": data["type"],
            "amount": amount_str,
            "senderPublicKey": data["sender_public_key"],
            "receiverPublicKey": data["receiver_public_key"],
            "signature": signature,
            "timestamp": timestamp,
        }
        if data.get("metadata") is not None:
            ledger_entry["metadata"] = data["metadata"]

        existing = store.get_ledger_transaction(transaction_id)
        if existing:
            return error("Transaktion existiert bereits", 409)

        try:
            store.append_ledger_transaction(ledger_entry)
        except ValueError as exc:
            message = str(exc)
            status = 409 if "existiert" in message.lower() else 400
            return error(message, status)

        return jsonify({
            "transactionId": transaction_id,
            "ledgerEntry": ledger_entry,
            "storedAt": now_iso(),
        }), 201

    @bp.get("/api/transactions/verify/<string:transaction_id>")
    def transactions_verify(transaction_id: str) -> Any:
        getter = getattr(store, "get_ledger_transaction", None)
        if not callable(getter):
            return error("Ledger-Speicher nicht verfügbar", 503)

        record = getter(transaction_id)
        if not record:
            return error("Transaktion nicht gefunden", 404)

        missing_fields = [
            field
            for field in ("type", "senderPublicKey", "receiverPublicKey", "amount", "timestamp", "signature")
            if not record.get(field)
        ]
        if missing_fields:
            return jsonify(
                {
                    "transactionId": transaction_id,
                    "verified": False,
                    "reason": f"Felder fehlen: {', '.join(missing_fields)}",
                    "ledgerEntry": record,
                }
            )

        amount_str = str(record.get("amount"))
        timestamp = str(record.get("timestamp"))
        signature = str(record.get("signature"))

        verified = verify_signature(
            str(record.get("type")),
            str(record.get("senderPublicKey")),
            str(record.get("receiverPublicKey")),
            amount_str,
            timestamp,
            signature,
        )

        response_body: Dict[str, Any] = {
            "transactionId": transaction_id,
            "verified": bool(verified),
            "verifiedAt": now_iso(),
            "ledgerEntry": record,
        }
        if not verified:
            response_body["reason"] = "Signatur ungültig"
        return jsonify(response_body)

    app.register_blueprint(bp)
