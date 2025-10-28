import pytest

from server import MemoryStore


@pytest.fixture()
def store() -> MemoryStore:
    return MemoryStore()


def _create_user(store: MemoryStore, username: str = "acct_test") -> None:
    store.create_user(
        username,
        {
            "username": username,
            "email": f"{username}@example.com",
            "first_name": "Test",
            "last_name": "User",
            "iban": "DE44500105175407324931",
            "salt": "salt",
            "password_hash": "hash",
            "balance": "0.00",
            "advisor_id": "advisor_sven",
        },
    )


def test_user_key_material_roundtrip(store: MemoryStore) -> None:
    _create_user(store)
    payload = {
        "version": 1,
        "salt": "c2FsdA==",
        "nonce": "bm9uY2U=",
        "ciphertext": "Y2lwaGVydGV4dA==",
    }
    store.set_user_key_material(
        "acct_test",
        public_key="public",
        encrypted_private_key=payload,
        created_at="2025-01-01T00:00:00Z",
    )
    result = store.get_user_key_material("acct_test")
    assert result is not None
    assert result["publicKey"] == "public"
    assert result["encryptedPrivateKey"] == payload

    store.delete_user_key_material("acct_test")
    assert store.get_user_key_material("acct_test") is None


def test_set_user_key_material_requires_user(store: MemoryStore) -> None:
    with pytest.raises(KeyError):
        store.set_user_key_material(
            "missing",
            public_key="public",
            encrypted_private_key={"version": 1},
            created_at="2025-01-01T00:00:00Z",
        )


def test_ledger_transaction_append_and_list(store: MemoryStore) -> None:
    txn = {
        "transactionId": "txn_1",
        "amount": "10.00",
        "timestamp": "2025-01-01T00:00:00Z",
    }
    store.append_ledger_transaction(txn)
    assert store.get_ledger_transaction("txn_1") == txn
    with pytest.raises(ValueError):
        store.append_ledger_transaction(txn)

    txn2 = {
        "transactionId": "txn_2",
        "amount": "5.00",
        "timestamp": "2025-01-02T00:00:00Z",
    }
    store.append_ledger_transaction(txn2)

    listed = store.list_ledger_transactions()
    assert [item["transactionId"] for item in listed] == ["txn_1", "txn_2"]
    listed_after_first = store.list_ledger_transactions(after_transaction_id="txn_1")
    assert [item["transactionId"] for item in listed_after_first] == ["txn_2"]


def test_bank_instance_registry(store: MemoryStore) -> None:
    data = {
        "host": "https://bank-a.example",
        "publicKey": "pub",
        "createdAt": "2025-01-01T00:00:00Z",
    }
    store.register_bank_instance("bank-a", data)
    with pytest.raises(ValueError):
        store.register_bank_instance("bank-a", data)

    fetched = store.get_bank_instance("bank-a")
    assert fetched and fetched["instanceId"] == "bank-a"

    updated = data | {"lastSeen": "2025-01-01T12:00:00Z"}
    store.upsert_bank_instance("bank-a", updated)
    fetched2 = store.get_bank_instance("bank-a")
    assert fetched2 and fetched2["lastSeen"] == "2025-01-01T12:00:00Z"

    store.upsert_bank_instance("bank-b", data)
    ids = sorted(item["instanceId"] for item in store.list_bank_instances())
    assert ids == ["bank-a", "bank-b"]

    store.delete_bank_instance("bank-a")
    assert store.get_bank_instance("bank-a") is None


def test_sync_state_management(store: MemoryStore) -> None:
    payload = {"lastTransactionId": "txn_9"}
    store.set_sync_state("bank-a", payload)
    assert store.get_sync_state("bank-a") == payload
    store.set_sync_state("bank-b", {"lastTransactionId": "txn_10"})
    states = {item["lastTransactionId"] for item in store.list_sync_states()}
    assert states == {"txn_9", "txn_10"}
    store.delete_sync_state("bank-a")
    assert store.get_sync_state("bank-a") is None
