"""Ledger-bezogene API-Endpunkte."""

from typing import Any

from flask import Blueprint, jsonify

bp = Blueprint("ledger", __name__)


def register(app, ctx) -> None:
    """Registriert alle Ledger-Routen."""
    store = ctx.store
    error = ctx.error
    require_ledger_token = ctx.require_ledger_token
    ledger_error_response = ctx.ledger_error_response
    get_configured_nodes = ctx.get_configured_ledger_nodes

    def _auto_managed_response() -> Any:
        try:
            require_ledger_token()
        except PermissionError as exc:
            return ledger_error_response(exc)
        return error("Ledger-Instanzen werden automatisch verwaltet", 405)

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
            entry = {"baseUrl": base_url}
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
        lister = getattr(store, "list_bank_instances", None)
        instances = lister() if callable(lister) else []
        return jsonify({"instances": instances})

    @bp.post("/api/ledger/instances")
    def ledger_instances_register() -> Any:
        return _auto_managed_response()

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
        return _auto_managed_response()

    @bp.post("/api/ledger/instances/<string:instance_id>/heartbeat")
    def ledger_instances_heartbeat(instance_id: str) -> Any:
        return _auto_managed_response()

    @bp.delete("/api/ledger/instances/<string:instance_id>")
    def ledger_instances_delete(instance_id: str) -> Any:
        return _auto_managed_response()

    app.register_blueprint(bp)
