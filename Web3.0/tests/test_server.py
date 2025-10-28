from decimal import Decimal

from crypto_utils import decrypt_private_key, sign_message_b64

import server


server.LEDGER_API_TOKEN = "test-ledger-token"


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ledger_header(token: str | None = None) -> dict[str, str]:
    value = token if token is not None else server.LEDGER_API_TOKEN
    return {"X-Ledger-Token": value}


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
    assert data.get("publicKey")
    assert data.get("keyCreatedAt")
    assert data.get("encryptedPrivateKey")
    account_id = server.store.resolve_username_by_email(payload["email"].lower())
    assert account_id
    return data, payload, account_id


def _get_private_key(account_id: str, password: str) -> bytes:
    material = server.store.get_user_key_material(account_id)
    assert material is not None
    return decrypt_private_key(password, material["encryptedPrivateKey"], pepper=server.USER_KEY_PEPPER)


def _sign_transaction(
    *,
    txn_type: str,
    sender_public_key: str,
    receiver_public_key: str,
    amount: str,
    timestamp: str,
    private_key: bytes,
) -> str:
    message = server._build_transaction_message(
        txn_type,
        sender_public_key,
        receiver_public_key,
        amount,
        timestamp,
    )
    return sign_message_b64(private_key, message)


def test_register_creates_account_with_initial_deposit(client):
    register_response, payload, account_id = _register_user(
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
    assert account["publicKey"]
    assert account["bankPublicKey"]
    assert account["encryptedPrivateKey"]
    assert account["accountId"] == account_id


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
    register_response, payload, account_id = _register_user(
        client,
        email="carol@example.com",
        first_name="Carol",
        last_name="Clark",
    )
    token = register_response["token"]

    private_key = _get_private_key(account_id, payload["password"])
    public_key = register_response["publicKey"]
    timestamp = server._now_iso()
    amount_str = "50.00"
    signature = _sign_transaction(
        txn_type="deposit",
        sender_public_key=public_key,
        receiver_public_key=public_key,
        amount=amount_str,
        timestamp=timestamp,
        private_key=private_key,
    )

    deposit_response = client.post(
        "/api/accounts/deposit",
        headers=_auth_header(token),
        json={"amount": "50", "timestamp": timestamp, "signature": signature},
    )
    assert deposit_response.status_code == 200
    assert deposit_response.get_json()["balance"] == "50.00"
    assert deposit_response.get_json()["transactionId"]

    me_response = client.get("/api/accounts/me", headers=_auth_header(token))
    transactions = me_response.get_json()["transactions"]
    assert transactions
    assert transactions[0]["type"] == "deposit"
    assert transactions[0]["amount"] == "50.00"
    assert transactions[0]["transactionId"]
    assert transactions[0]["signature"]


def test_transfer_between_accounts_updates_both_ledgers(client):
    sender_response, sender_payload, sender_account = _register_user(
        client,
        email="dana@example.com",
        first_name="Dana",
        last_name="Doe",
        initial="200",
    )
    receiver_response, receiver_payload, receiver_account = _register_user(
        client,
        email="eric@example.com",
        first_name="Eric",
        last_name="Evans",
    )

    sender_private_key = _get_private_key(sender_account, sender_payload["password"])
    sender_public_key = sender_response["publicKey"]
    receiver_public_key = receiver_response["publicKey"]
    timestamp = server._now_iso()
    amount_str = "75.00"
    signature = _sign_transaction(
        txn_type="transfer",
        sender_public_key=sender_public_key,
        receiver_public_key=receiver_public_key,
        amount=amount_str,
        timestamp=timestamp,
        private_key=sender_private_key,
    )

    transfer_response = client.post(
        "/api/accounts/transfer",
        headers=_auth_header(sender_response["token"]),
        json={
            "targetIban": receiver_response["iban"],
            "targetFirstName": receiver_payload["firstName"],
            "targetLastName": receiver_payload["lastName"],
            "amount": "75",
            "timestamp": timestamp,
            "signature": signature,
        },
    )
    assert transfer_response.status_code == 200
    assert transfer_response.get_json()["balance"] == "125.00"
    assert transfer_response.get_json()["transactionId"]

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
    assert receiver_txn["transactionId"] == sender_txn["transactionId"]
    assert sender_txn["signature"]
    assert receiver_txn["signature"] == sender_txn["signature"]


def test_account_resolve_returns_public_key(client):
    sender_response, sender_payload, sender_account = _register_user(
        client,
        email="fiona@example.com",
        first_name="Fiona",
        last_name="Fuchs",
    )
    target_response, _, _ = _register_user(
        client,
        email="greg@example.com",
        first_name="Greg",
        last_name="Gruber",
    )

    resolve = client.post(
        "/api/accounts/resolve",
        headers=_auth_header(sender_response["token"]),
        json={"targetIban": target_response["iban"]},
    )
    assert resolve.status_code == 200
    data = resolve.get_json()
    assert data["publicKey"] == target_response["publicKey"]


def test_update_profile_changes_names_and_email(client):
    register_response, payload, account_id = _register_user(
        client,
        email="harry@example.com",
        first_name="Harry",
        last_name="Huber",
    )

    update_response = client.put(
        "/api/accounts/me",
        headers=_auth_header(register_response["token"]),
        json={
            "firstName": "Harald",
            "lastName": "Hauser",
            "email": "harald.hauser@example.com",
        },
    )
    assert update_response.status_code == 200
    assert update_response.get_json() == {"success": True}

    updated_user = server.store.get_user(account_id)
    assert updated_user["first_name"] == "Harald"
    assert updated_user["last_name"] == "Hauser"
    assert updated_user["email"] == "harald.hauser@example.com"

    # Anmeldung funktioniert mit neuer E-Mail
    login_response = client.post(
        "/api/auth/login",
        json={"email": "harald.hauser@example.com", "password": payload["password"]},
    )
    assert login_response.status_code == 200


def test_update_profile_rejects_duplicate_email(client):
    first_response, _, _ = _register_user(
        client,
        email="ida@example.com",
        first_name="Ida",
        last_name="Imhof",
    )
    second_response, _, _ = _register_user(
        client,
        email="jonas@example.com",
        first_name="Jonas",
        last_name="Jung",
    )

    conflict = client.put(
        "/api/accounts/me",
        headers=_auth_header(first_response["token"]),
        json={
            "firstName": "Ida",
            "lastName": "Imhof",
            "email": "jonas@example.com",
        },
    )
    assert conflict.status_code == 409
    assert conflict.get_json()["error"] == "E-Mail existiert bereits"


def test_user_keypair_get_returns_current_material(client):
    register_response, _, account_id = _register_user(
        client,
        email="kira@example.com",
        first_name="Kira",
        last_name="Klein",
    )

    response = client.get("/api/user/keypair", headers=_auth_header(register_response["token"]))
    assert response.status_code == 200
    data = response.get_json()
    assert data["publicKey"] == register_response["publicKey"]
    assert data["createdAt"] == register_response["keyCreatedAt"]
    assert data["encryptedPrivateKey"] == register_response["encryptedPrivateKey"]

    material = server.store.get_user_key_material(account_id)
    assert material["publicKey"] == data["publicKey"]


def test_user_keypair_rotate_creates_new_material(client):
    register_response, payload, account_id = _register_user(
        client,
        email="leah@example.com",
        first_name="Leah",
        last_name="Lang",
    )

    rotate = client.post(
        "/api/user/keypair",
        headers=_auth_header(register_response["token"]),
        json={"password": payload["password"], "exposePrivateKey": True},
    )
    assert rotate.status_code == 201
    data = rotate.get_json()
    assert data["publicKey"] != register_response["publicKey"]
    assert data["previousPublicKey"] == register_response["publicKey"]
    assert "privateKey" in data

    stored = server.store.get_user_key_material(account_id)
    assert stored["publicKey"] == data["publicKey"]


def test_user_keypair_delete_revokes_material(client):
    register_response, payload, account_id = _register_user(
        client,
        email="mila@example.com",
        first_name="Mila",
        last_name="Maier",
    )

    delete_response = client.delete(
        "/api/user/keypair",
        headers=_auth_header(register_response["token"]),
        json={"password": payload["password"]},
    )
    assert delete_response.status_code == 200
    data = delete_response.get_json()
    assert data["success"] is True
    assert data["revokedPublicKey"] == register_response["publicKey"]
    assert server.store.get_user_key_material(account_id) is None


def test_admin_transactions_list_filters_by_partner(client):
    register_response, payload, account_id = _register_user(
        client,
        email="nina@example.com",
        first_name="Nina",
        last_name="Neu",
        initial="100",
    )

    private_key = _get_private_key(account_id, payload["password"])
    timestamp = server._now_iso()
    signature = _sign_transaction(
        txn_type="deposit",
        sender_public_key=register_response["publicKey"],
        receiver_public_key=register_response["publicKey"],
        amount="25.00",
        timestamp=timestamp,
        private_key=private_key,
    )

    client.post(
        "/api/accounts/deposit",
        headers=_auth_header(register_response["token"]),
        json={"amount": "25", "timestamp": timestamp, "signature": signature},
    )

    list_response = client.get(
        "/api/transactions",
        headers=_ledger_header(),
        query_string={"limit": 5, "partner": register_response["publicKey"]},
    )
    assert list_response.status_code == 200
    entries = list_response.get_json()["transactions"]
    assert entries
    assert all(
        entry["senderPublicKey"] == register_response["publicKey"]
        or entry["receiverPublicKey"] == register_response["publicKey"]
        for entry in entries
    )
def test_ledger_transactions_put_and_verify(client):
    register_response, payload, _ = _register_user(
        client,
        email="oliver@example.com",
        first_name="Oliver",
        last_name="Ort",
    )

    account_id = server.store.resolve_username_by_email("oliver@example.com")
    assert account_id
    private_key = _get_private_key(account_id, payload["password"])
    timestamp = server._now_iso()
    amount_str = "10.00"
    signature = _sign_transaction(
        txn_type="deposit",
        sender_public_key=register_response["publicKey"],
        receiver_public_key=register_response["publicKey"],
        amount=amount_str,
        timestamp=timestamp,
        private_key=private_key,
    )

    txn_id = "txn_manual_1"
    upsert_response = client.put(
        f"/api/transactions/{txn_id}",
        headers=_ledger_header(),
        json={
            "type": "deposit",
            "amount": amount_str,
            "timestamp": timestamp,
            "senderPublicKey": register_response["publicKey"],
            "receiverPublicKey": register_response["publicKey"],
            "signature": signature,
            "metadata": {"source": "manual"},
        },
    )
    assert upsert_response.status_code == 201
    payload_body = upsert_response.get_json()
    assert payload_body["transactionId"] == txn_id

    verify_response = client.get(
        f"/api/transactions/verify/{txn_id}",
        headers=_ledger_header(),
    )
    assert verify_response.status_code == 200
    verify_data = verify_response.get_json()
    assert verify_data["verified"] is True
    assert verify_data["ledgerEntry"]["metadata"]["source"] == "manual"


def test_admin_transaction_verify_reports_invalid_signature(client):
    register_response, payload, _ = _register_user(
        client,
        email="pia@example.com",
        first_name="Pia",
        last_name="Pohl",
    )

    timestamp = server._now_iso()
    txn_id = "txn_manual_invalid"
    upsert_response = client.put(
        f"/api/transactions/{txn_id}",
        headers=_ledger_header(),
        json={
            "type": "deposit",
            "amount": "5.00",
            "timestamp": timestamp,
            "senderPublicKey": register_response["publicKey"],
            "receiverPublicKey": register_response["publicKey"],
            "signature": "invalid",
            "skipSignatureCheck": True,
        },
    )
    assert upsert_response.status_code == 201

    verify_response = client.get(
        f"/api/transactions/verify/{txn_id}",
        headers=_ledger_header(),
    )
    assert verify_response.status_code == 200
    verify_data = verify_response.get_json()
    assert verify_data["verified"] is False
    assert verify_data["reason"] == "Signatur ungültig"


def test_admin_transactions_require_token(client):
    response = client.get("/api/transactions")
    assert response.status_code == 401
    assert response.get_json()["error"] == "Ledger-Token fehlt"


def test_transactions_export_returns_all_entries(client):
    register_response, payload, account_id = _register_user(
        client,
        email="quentin@example.com",
        first_name="Quentin",
        last_name="Quast",
        initial="50",
    )

    private_key = _get_private_key(account_id, payload["password"])
    timestamp = server._now_iso()
    signature = _sign_transaction(
        txn_type="deposit",
        sender_public_key=register_response["publicKey"],
        receiver_public_key=register_response["publicKey"],
        amount="20.00",
        timestamp=timestamp,
        private_key=private_key,
    )

    client.put(
        "/api/transactions/txn_export_1",
        headers=_ledger_header(),
        json={
            "type": "deposit",
            "amount": "20.00",
            "timestamp": timestamp,
            "senderPublicKey": register_response["publicKey"],
            "receiverPublicKey": register_response["publicKey"],
            "signature": signature,
        },
    )

    export_response = client.get(
        "/api/transactions/export",
        headers=_ledger_header(),
    )
    assert export_response.status_code == 200
    transactions = export_response.get_json()["transactions"]
    ids = {entry["transactionId"] for entry in transactions}
    assert "txn_export_1" in ids


def test_ledger_instances_register_list_and_heartbeat(client):
    headers = _ledger_header()
    register_response = client.post(
        "/api/ledger/instances",
        headers=headers,
        json={
            "instanceId": "bank-a",
            "baseUrl": "https://bank-a.example",
            "publicKey": "PUBKEY",
            "metadata": {"region": "EU"},
        },
    )
    assert register_response.status_code == 201
    stored = register_response.get_json()
    assert stored["instanceId"] == "bank-a"
    assert stored["metadata"]["region"] == "EU"

    list_response = client.get("/api/ledger/instances", headers=headers)
    assert list_response.status_code == 200
    instances = list_response.get_json()["instances"]
    assert any(item["instanceId"] == "bank-a" for item in instances)

    heartbeat_response = client.post(
        "/api/ledger/instances/bank-a/heartbeat",
        headers=headers,
        json={"status": "online"},
    )
    assert heartbeat_response.status_code == 200
    heartbeat_payload = heartbeat_response.get_json()
    assert heartbeat_payload["status"] == "online"

    delete_response = client.delete("/api/ledger/instances/bank-a", headers=headers)
    assert delete_response.status_code == 200
    assert delete_response.get_json()["success"] is True


def test_ledger_instances_put_creates_and_updates(client):
    headers = _ledger_header()
    create_response = client.put(
        "/api/ledger/instances/bank-b",
        headers=headers,
        json={"baseUrl": "bank-b.example", "status": "init"},
    )
    assert create_response.status_code == 201
    created_payload = create_response.get_json()
    assert created_payload["baseUrl"] == "https://bank-b.example"

    update_response = client.put(
        "/api/ledger/instances/bank-b",
        headers=headers,
        json={"metadata": {"clusters": 2}, "status": "active"},
    )
    assert update_response.status_code == 200
    updated_payload = update_response.get_json()
    assert updated_payload["metadata"]["clusters"] == 2
    assert updated_payload["status"] == "active"
