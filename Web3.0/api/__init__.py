"""API-Blueprint-Registrierung für das Web3.0-Backend."""

from . import accounts, auth, ledger, transactions, user


def register_apis(app, ctx) -> None:
    """Registriert alle API-Blueprints am Flask-App-Objekt."""
    ledger.register(app, ctx)
    auth.register(app, ctx)
    user.register(app, ctx)
    accounts.register(app, ctx)
    transactions.register(app, ctx)
