from decimal import Decimal

import server


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _register_user(client, *, email: str, first_name: str, last_name: str, initial: str = "0"):
    payload = {
        "email": email,
        "password": "Secret123",
        "firstName": first_name,
        "lastName": last_name,
    }
    if Decimal(initial) > Decimal("0"):
        payload["initialDeposit"] = initial
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data and "token" in data
    return data, payload


def test_register_creates_account_with_initial_deposit(client):
    register_response, payload = _register_user(
        client,
        email="alice@example.com",
        first_name="Alice",
        last_name="Anderson",
        initial="150.50",
    )

    token = register_response["token"]
    me_response = client.get("/api/accounts/me", headers=_auth_header(token))
    assert me_response.status_code == 200
    account = me_response.get_json()
    assert account["email"] == payload["email"].lower()
    assert account["balance"] == "150.50"
    assert account["transactions"][0]["type"] == "deposit"
    assert account["transactions"][0]["memo"] == "Initiale Einzahlung"


def test_login_with_wrong_password_is_rejected(client):
    _register_user(
        client,
        email="bob@example.com",
        first_name="Bob",
        last_name="Baker",
    )

    response = client.post(
        "/api/auth/login",
        json={"email": "bob@example.com", "password": "Wrong123"},
    )
    assert response.status_code == 401
    assert response.get_json()["error"] == "Ungültige Zugangsdaten"


def test_deposit_updates_balance_and_records_transaction(client):
    register_response, _ = _register_user(
        client,
        email="carol@example.com",
        first_name="Carol",
        last_name="Clark",
    )
    token = register_response["token"]

    deposit_response = client.post(
        "/api/accounts/deposit",
        headers=_auth_header(token),
        json={"amount": "50"},
    )
    assert deposit_response.status_code == 200
    assert deposit_response.get_json()["balance"] == "50.00"

    me_response = client.get("/api/accounts/me", headers=_auth_header(token))
    transactions = me_response.get_json()["transactions"]
    assert transactions
    assert transactions[0]["type"] == "deposit"
    assert transactions[0]["amount"] == "50.00"


def test_transfer_between_accounts_updates_both_ledgers(client):
    sender_response, sender_payload = _register_user(
        client,
        email="dana@example.com",
        first_name="Dana",
        last_name="Doe",
        initial="200",
    )
    receiver_response, receiver_payload = _register_user(
        client,
        email="eric@example.com",
        first_name="Eric",
        last_name="Evans",
    )

    transfer_response = client.post(
        "/api/accounts/transfer",
        headers=_auth_header(sender_response["token"]),
        json={
            "targetIban": receiver_response["iban"],
            "targetFirstName": receiver_payload["firstName"],
            "targetLastName": receiver_payload["lastName"],
            "amount": "75",
        },
    )
    assert transfer_response.status_code == 200
    assert transfer_response.get_json()["balance"] == "125.00"

    sender_account = client.get(
        "/api/accounts/me",
        headers=_auth_header(sender_response["token"]),
    ).get_json()
    receiver_account = client.get(
        "/api/accounts/me",
        headers=_auth_header(receiver_response["token"]),
    ).get_json()

    sender_txn = sender_account["transactions"][0]
    receiver_txn = receiver_account["transactions"][0]

    assert sender_txn["type"] == "transfer_out"
    assert sender_txn["amount"] == "-75.00"
    assert sender_txn["counterpartyIban"] == receiver_response["iban"]

    assert receiver_txn["type"] == "transfer_in"
    assert receiver_txn["amount"] == "75.00"
    assert receiver_txn["counterpartyIban"] == sender_account["iban"]
    assert receiver_txn["counterpartyName"] == f"{sender_payload['firstName']} {sender_payload['lastName']}"
