"""Ledger-bezogene API-Endpunkte."""

from typing import Any, Dict

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

bp = Blueprint("ledger", __name__)


def register(app, ctx) -> None:
    """Registriert alle Ledger-Routen."""
    store = ctx.store
    error = ctx.error
    require_ledger_token = ctx.require_ledger_token
    ledger_error_response = ctx.ledger_error_response
    get_configured_nodes = ctx.get_configured_ledger_nodes
    register_schema = ctx.ledger_instance_register_schema
    update_schema = ctx.ledger_instance_update_schema
    heartbeat_schema = ctx.ledger_heartbeat_schema
    normalize_base_url = ctx.normalize_base_url
    now_iso = ctx.now_iso

    def _ledger_instances_store_available() -> bool:
        required = (
            "list_bank_instances",
            "register_bank_instance",
            "upsert_bank_instance",
            "delete_bank_instance",
        )
        return all(callable(getattr(store, attr, None)) for attr in required)

    def _apply_instance_update(instance_id: str, update: Dict[str, Any], *, require_existing: bool = False) -> Dict[str, Any]:
        getter = getattr(store, "get_bank_instance", None)
        if not callable(getter):  # pragma: no cover - defensive guard
            raise RuntimeError("Bankinstanzen können derzeit nicht verwaltet werden")

        existing = getter(instance_id)
        if require_existing and not existing:
            raise LookupError("Instanz nicht gefunden")

        record = existing.copy() if existing else {}

        if "base_url" in update and update["base_url"] is not None:
            record["baseUrl"] = normalize_base_url(update["base_url"])
        if "public_key" in update and update["public_key"] is not None:
            record["publicKey"] = update["public_key"]
        if "token" in update:
            token_value = (update.get("token") or "").strip()
            if token_value:
                record["token"] = token_value
            else:
                record.pop("token", None)
        if "metadata" in update and update["metadata"] is not None:
            record["metadata"] = update["metadata"]
        if "status" in update and update["status"] is not None:
            record["status"] = update["status"]
        if "last_seen" in update and update["last_seen"] is not None:
            record["lastSeen"] = update["last_seen"]
        else:
            record["lastSeen"] = now_iso()

        store.upsert_bank_instance(instance_id, record)
        updated = getter(instance_id)
        if not updated:  # pragma: no cover - defensive guard
            raise LookupError("Instanz nicht gefunden")
        return updated

    @bp.get("/api/ledger/nodes")
    def ledger_nodes() -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)

        nodes_payload = []
        for node in get_configured_nodes():
            base_url = node.get("base_url")
            if not base_url:
                continue
            entry: Dict[str, Any] = {"baseUrl": base_url}
            token = node.get("token")
            if token:
                entry["token"] = token
            nodes_payload.append(entry)
        return jsonify({"nodes": nodes_payload})

    @bp.get("/api/ledger/instances")
    def ledger_instances_list() -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)

        if not _ledger_instances_store_available():  # pragma: no cover - defensive guard
            return jsonify({"instances": []})

        instances = store.list_bank_instances()
        return jsonify({"instances": instances})

    @bp.post("/api/ledger/instances")
    def ledger_instances_register() -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)

        if not _ledger_instances_store_available():  # pragma: no cover - defensive guard
            return error("Bankinstanzen können derzeit nicht verwaltet werden", 503)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            data = register_schema.load(payload)
        except ValidationError as exc:
            return error(ctx.validation_error_message(exc), 400)

        instance_id = data["instance_id"].strip()
        try:
            base_url = normalize_base_url(data["base_url"])
        except ValueError as exc:
            return error(str(exc))

        record: Dict[str, Any] = {
            "baseUrl": base_url,
            "lastSeen": data.get("last_seen") or now_iso(),
        }
        if data.get("public_key") is not None:
            record["publicKey"] = data["public_key"]
        token_value = (data.get("token") or "").strip()
        if token_value:
            record["token"] = token_value
        if data.get("metadata") is not None:
            record["metadata"] = data["metadata"]
        if data.get("status") is not None:
            record["status"] = data["status"]

        try:
            store.register_bank_instance(instance_id, record)
        except ValueError as exc:
            message = str(exc)
            status = 409 if "existiert" in message.lower() else 400
            return error(message, status)

        stored = store.get_bank_instance(instance_id)
        return jsonify(stored), 201

    @bp.get("/api/ledger/instances/<string:instance_id>")
    def ledger_instances_get(instance_id: str) -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)

        getter = getattr(store, "get_bank_instance", None)
        if not callable(getter):  # pragma: no cover - defensive guard
            return error("Bankinstanzen können derzeit nicht verwaltet werden", 503)

        record = getter(instance_id)
        if not record:
            return error("Instanz nicht gefunden", 404)
        return jsonify(record)

    @bp.put("/api/ledger/instances/<string:instance_id>")
    def ledger_instances_update(instance_id: str) -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)

        if not _ledger_instances_store_available():  # pragma: no cover - defensive guard
            return error("Bankinstanzen können derzeit nicht verwaltet werden", 503)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            data = update_schema.load(payload)
        except ValidationError as exc:
            return error(ctx.validation_error_message(exc), 400)

        existing = store.get_bank_instance(instance_id) if callable(getattr(store, "get_bank_instance", None)) else None
        if existing is None and data.get("base_url") in (None, ""):
            return error("baseUrl wird für neue Instanzen benötigt")
        try:
            updated = _apply_instance_update(instance_id, data)
        except LookupError:
            return error("Instanz nicht gefunden", 404)
        except ValueError as exc:
            return error(str(exc))

        status_code = 200 if existing else 201
        return jsonify(updated), status_code

    @bp.post("/api/ledger/instances/<string:instance_id>/heartbeat")
    def ledger_instances_heartbeat(instance_id: str) -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)

        if not _ledger_instances_store_available():  # pragma: no cover - defensive guard
            return error("Bankinstanzen können derzeit nicht verwaltet werden", 503)

        payload = request.get_json(force=True, silent=True) or {}
        try:
            data = heartbeat_schema.load(payload)
        except ValidationError as exc:
            return error(ctx.validation_error_message(exc), 400)

        try:
            update_payload = {
                "status": data.get("status"),
                "metadata": data.get("metadata"),
                "last_seen": now_iso(),
            }
            updated = _apply_instance_update(instance_id, update_payload, require_existing=True)
        except LookupError:
            return error("Instanz nicht gefunden", 404)
        except ValueError as exc:
            return error(str(exc))

        return jsonify(updated)

    @bp.delete("/api/ledger/instances/<string:instance_id>")
    def ledger_instances_delete(instance_id: str) -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)

        deleter = getattr(store, "delete_bank_instance", None)
        if not callable(deleter):  # pragma: no cover - defensive guard
            return error("Bankinstanzen können derzeit nicht verwaltet werden", 503)

        deleter(instance_id)
        return jsonify({"success": True})

    app.register_blueprint(bp)
