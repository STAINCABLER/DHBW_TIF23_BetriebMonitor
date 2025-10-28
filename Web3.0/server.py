"""Flask-Anwendung für das Web3.0-Banking-Demo."""

import atexit
import base64
import binascii
import hashlib
import json
import logging
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request
from marshmallow import Schema, ValidationError, fields, validate

from crypto_utils import (
    DecryptionError,
    decrypt_private_key,
    encrypt_private_key,
    generate_user_keypair,
    sign_message_b64,
    verify_signature_b64,
)

try:
    from upstash_redis import Redis as UpstashRedis
except ImportError:  # pragma: no cover - optional dependency
    UpstashRedis = None  # type: ignore[assignment]


load_dotenv()

LOGGER = logging.getLogger("altebank.web3")
LOGGER.addHandler(logging.NullHandler())

APP_SECRET = os.getenv("APP_SECRET_KEY") or secrets.token_hex(32)
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
SESSION_CLEANUP_INTERVAL_SECONDS = int(os.getenv("SESSION_CLEANUP_INTERVAL_SECONDS", "600"))

LEDGER_API_TOKEN = os.getenv("LEDGER_API_TOKEN", "").strip()
LEDGER_SYNC_INTERVAL_SECONDS = int(os.getenv("LEDGER_SYNC_INTERVAL_SECONDS", "60"))

user_key_pepper_raw = os.getenv("USER_KEY_ENC_SECRET", "").strip()
USER_KEY_PEPPER: Optional[bytes] = user_key_pepper_raw.encode("utf-8") if user_key_pepper_raw else None

BANK_PUBLIC_KEY = os.getenv("BANK_PUBLIC_KEY", "BANK_SYSTEM").strip()

_BALANCE_ADJUST_SCRIPT = """
local key = KEYS[1]
local delta = tonumber(ARGV[1])
if not delta then
    return "ERR_BAD_DELTA"
end
local balance = redis.call('HGET', key, 'balance')
if not balance then
    return "ERR_NOT_FOUND"
end
local new_balance = tonumber(balance) + delta
if new_balance < 0 then
    return "ERR_INSUFFICIENT"
end
redis.call('HSET', key, 'balance', string.format('%.2f', new_balance))
return string.format('%.2f', new_balance)
""".strip()

def _parse_csv_env(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_token_and_url(entry: str, *, default_token: Optional[str] = None) -> Optional[Dict[str, str]]:
    candidate = entry.strip()
    if not candidate:
        return None
    token: Optional[str] = None
    url = candidate

    if "@https://" in candidate or "@http://" in candidate:
        token, url = candidate.split("@", 1)
    elif candidate.count("@") == 1 and "://" not in candidate:
        token, url = candidate.split("@", 1)

    url = url.strip()
    if not url.startswith(("https://", "http://")):
        url = f"https://{url}"
    url = url.rstrip("/")

    token = (token or default_token or "").strip()
    return {"base_url": url, "token": token} if url else None


def _ledger_headers(token: str) -> Dict[str, str]:
    return {"X-Ledger-Token": token} if token else {}


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NAME_RE = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ' -]{2,50}$")
GERMAN_IBAN_RE = re.compile(r"^DE\d{20}$")

ADVISORS: List[Dict[str, str]] = [
    {
        "id": "advisor_sven",
        "name": "Sven Meyer",
        "title": "Senior Kundenberater",
        "phone": "0711 204010",
        "email": "sven.meyer@altebank.de",
        "image": "assets/advisors/advisor-1.svg",
    },
    {
        "id": "advisor_jana",
        "name": "Jana Roth",
        "title": "Finanzexpertin",
        "phone": "0711 204011",
        "email": "jana.roth@altebank.de",
        "image": "assets/advisors/advisor-2.svg",
    },
    {
        "id": "advisor_noah",
        "name": "Noah Hartmann",
        "title": "Privatkunden Spezialist",
        "phone": "0711 204012",
        "email": "noah.hartmann@altebank.de",
        "image": "assets/advisors/advisor-3.svg",
    },
    {
        "id": "advisor_elena",
        "name": "Elena Vogt",
        "title": "Vermögensberatung",
        "phone": "0711 204013",
        "email": "elena.vogt@altebank.de",
        "image": "assets/advisors/advisor-4.svg",
    },
    {
        "id": "advisor_malik",
        "name": "Malik Demir",
        "title": "KMU Betreuung",
        "phone": "0711 204014",
        "email": "malik.demir@altebank.de",
        "image": "assets/advisors/advisor-5.svg",
    },
]

DEFAULT_ADVISOR: Dict[str, str] = ADVISORS[0]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _format_amount(value: Decimal) -> str:
    return str(value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _parse_amount(raw: Any) -> Decimal:
    if raw in (None, ""):
        raise ValueError("Betrag fehlt")
    try:
        return Decimal(str(raw))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("Ungültiger Betrag") from exc


def _validation_error_message(error: ValidationError) -> str:
    messages: List[str] = []
    for field, issues in error.messages.items():
        label = field if field != "_schema" else "Anfrage"
        for issue in issues:
            messages.append(f"{label}: {issue}")
    return "; ".join(messages) or "Ungültige Eingabedaten"


def _clean_email(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("Ungültige E-Mail-Adresse")
    email = raw.strip().lower()
    if not EMAIL_RE.match(email):
        raise ValueError("Ungültige E-Mail-Adresse")
    return email


def _clean_name(raw: Any, field: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"Ungültiger {field}")
    name = raw.strip()
    if not name:
        raise ValueError(f"{field} darf nicht leer sein")
    if not NAME_RE.match(name):
        raise ValueError(f"{field} enthält ungültige Zeichen")
    return name


def _iban_mod_97(sequence: str) -> int:
    remainder = 0
    for char in sequence:
        if char.isdigit():
            remainder = (remainder * 10 + int(char)) % 97
        else:
            remainder = (remainder * 100 + (ord(char.upper()) - 55)) % 97
    return remainder


def _clean_iban(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("Ungültige IBAN")
    iban = re.sub(r"\s+", "", raw).upper()
    if not GERMAN_IBAN_RE.match(iban):
        raise ValueError("IBAN muss mit DE beginnen und 22 Stellen haben")
    if _iban_mod_97(iban[4:] + iban[:4]) != 1:
        raise ValueError("IBAN ist ungültig")
    return iban


def _pick_random_advisor() -> Dict[str, str]:
    return secrets.choice(ADVISORS)


def _get_advisor_by_id(advisor_id: Optional[str]) -> Dict[str, str]:
    if not advisor_id:
        return DEFAULT_ADVISOR
    for advisor in ADVISORS:
        if advisor["id"] == advisor_id:
            return advisor
    return DEFAULT_ADVISOR


class _KeypairRotateSchema(Schema):
    password = fields.String(required=True, validate=validate.Length(min=6))
    expose_private_key = fields.Boolean(load_default=False, data_key="exposePrivateKey")


class _KeypairDeleteSchema(Schema):
    password = fields.String(required=True, validate=validate.Length(min=6))


class _TransactionsQuerySchema(Schema):
    partner = fields.String(load_default=None)
    limit = fields.Integer(load_default=100, validate=validate.Range(min=1, max=500))
    since_id = fields.String(load_default=None, data_key="sinceId")


class _TransactionsInjectionSchema(Schema):
    transaction_id = fields.String(load_default=None, data_key="transactionId")
    type = fields.String(
        required=True,
        validate=validate.OneOf(["deposit", "withdraw", "transfer", "custom"]),
    )
    amount = fields.Decimal(required=True, as_string=True, validate=validate.Range(min=Decimal("0"), min_inclusive=False))
    timestamp = fields.String(required=True)
    sender_public_key = fields.String(required=True, data_key="senderPublicKey")
    receiver_public_key = fields.String(required=True, data_key="receiverPublicKey")
    signature = fields.String(required=True)
    metadata = fields.Dict(keys=fields.String(), values=fields.Raw(), load_default=None)
    allow_update = fields.Boolean(load_default=False, data_key="allowUpdate")
    skip_signature_check = fields.Boolean(load_default=False, data_key="skipSignatureCheck")


_KEYPAIR_ROTATE_SCHEMA = _KeypairRotateSchema()
_KEYPAIR_DELETE_SCHEMA = _KeypairDeleteSchema()
_TRANSACTIONS_QUERY_SCHEMA = _TransactionsQuerySchema()
_TRANSACTIONS_INJECTION_SCHEMA = _TransactionsInjectionSchema()


class MemoryStore:
    """Einfacher Fallback, falls keine Redis-Verbindung verfügbar ist."""

    def __init__(self) -> None:
        self._users: Dict[str, Dict[str, Any]] = {}
        self._transactions: Dict[str, List[Dict[str, Any]]] = {}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._email_index: Dict[str, str] = {}
        self._iban_index: Dict[str, str] = {}
        self._user_keys: Dict[str, Dict[str, Any]] = {}
        self._ledger_transactions: Dict[str, Dict[str, Any]] = {}
        self._ledger_order: List[str] = []
        self._bank_instances: Dict[str, Dict[str, Any]] = {}
        self._bank_instance_order: List[str] = []
        self._sync_state: Dict[str, Dict[str, Any]] = {}

    # Benutzerverwaltung -------------------------------------------------
    def user_exists(self, username: str) -> bool:
        return username in self._users

    def create_user(self, username: str, data: Dict[str, Any]) -> None:
        if username in self._users:
            raise ValueError("Benutzer existiert bereits")
        email = str(data.get("email", "")).strip().lower()
        iban = str(data.get("iban", "")).replace(" ", "").upper()
        if not email or not iban:
            raise ValueError("E-Mail und IBAN werden benötigt")
        if email in self._email_index:
            raise ValueError("E-Mail existiert bereits")
        if iban in self._iban_index:
            raise ValueError("IBAN existiert bereits")
        data_copy = data.copy()
        data_copy["email"] = email
        data_copy["iban"] = iban
        self._users[username] = data_copy
        self._transactions[username] = []
        self._email_index[email] = username
        self._iban_index[iban] = username

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        data = self._users.get(username)
        return data.copy() if data else None

    def email_exists(self, email: str) -> bool:
        return email.lower() in self._email_index

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        username = self._email_index.get(email.lower())
        if not username:
            return None
        return self.get_user(username)

    def resolve_username_by_email(self, email: str) -> Optional[str]:
        return self._email_index.get(email.lower())

    def iban_exists(self, iban: str) -> bool:
        return iban.upper() in self._iban_index

    def get_user_by_iban(self, iban: str) -> Optional[Dict[str, Any]]:
        username = self._iban_index.get(iban.upper())
        if not username:
            return None
        return self.get_user(username)

    def resolve_username_by_iban(self, iban: str) -> Optional[str]:
        return self._iban_index.get(iban.upper())

    def set_user_field(self, username: str, field: str, value: Any) -> None:
        if username not in self._users:
            raise KeyError("Benutzer nicht gefunden")
        self._users[username][field] = value

    def update_user_profile(self, username: str, *, first_name: str, last_name: str, email: str) -> None:
        if username not in self._users:
            raise KeyError("Benutzer nicht gefunden")
        normalized_email = email.strip().lower()
        if not normalized_email:
            raise ValueError("E-Mail darf nicht leer sein")
        existing = self._email_index.get(normalized_email)
        if existing and existing != username:
            raise ValueError("E-Mail existiert bereits")

        user = self._users[username]
        old_email = str(user.get("email") or "").strip().lower()
        if old_email and old_email != normalized_email:
            self._email_index.pop(old_email, None)
        self._email_index[normalized_email] = username

        user["first_name"] = first_name
        user["last_name"] = last_name
        user["email"] = normalized_email

    def delete_user(self, username: str) -> None:
        if username not in self._users:
            raise KeyError("Benutzer nicht gefunden")
        user = self._users.pop(username)
        self._transactions.pop(username, None)
        self._user_keys.pop(username, None)
        email = str(user.get("email") or "").strip().lower()
        iban = str(user.get("iban") or "").replace(" ", "").upper()
        if email:
            self._email_index.pop(email, None)
        if iban:
            self._iban_index.pop(iban, None)
        for token, session in list(self._sessions.items()):
            if session.get("username") == username:
                self._sessions.pop(token, None)

    # Transaktionen ------------------------------------------------------
    def append_transaction(self, username: str, txn: Dict[str, Any]) -> None:
        self._transactions.setdefault(username, []).insert(0, txn)

    def get_transactions(self, username: str) -> List[Dict[str, Any]]:
        return [txn.copy() for txn in self._transactions.get(username, [])]

    # Kontostände --------------------------------------------------------
    def adjust_balance(self, username: str, delta: Decimal) -> Decimal:
        user = self._users.get(username)
        if not user:
            raise KeyError("Benutzer nicht gefunden")
        balance = Decimal(user.get("balance", "0")) + delta
        if balance < Decimal("0"):
            raise ValueError("Unzureichendes Guthaben")
        user["balance"] = _format_amount(balance)
        return balance

    # Sessions -----------------------------------------------------------
    def save_session(self, token: str, username: str, ttl_seconds: int) -> None:
        self._sessions[token] = {
            "username": username,
            "expires": datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
        }

    def get_session(self, token: str) -> Optional[str]:
        session = self._sessions.get(token)
        if not session:
            return None
        if session["expires"] < datetime.now(timezone.utc):
            self._sessions.pop(token, None)
            return None
        return session["username"]

    def delete_session(self, token: str) -> None:
        self._sessions.pop(token, None)

    def purge_stale_sessions(self) -> int:
        now = datetime.now(timezone.utc)
        removed = 0
        for token, meta in list(self._sessions.items()):
            expires = meta.get("expires")
            username = meta.get("username")
            is_expired = bool(expires and expires < now)
            user_missing = username is not None and not self.user_exists(username)
            if is_expired or user_missing:
                self._sessions.pop(token, None)
                removed += 1
        return removed

    # Schlüsselmaterial --------------------------------------------------
    def set_user_key_material(
        self,
        username: str,
        *,
        public_key: str,
        encrypted_private_key: Dict[str, Any],
        created_at: str,
    ) -> None:
        if username not in self._users:
            raise KeyError("Benutzer nicht gefunden")
        self._user_keys[username] = {
            "publicKey": public_key,
            "encryptedPrivateKey": json.loads(json.dumps(encrypted_private_key)),
            "createdAt": created_at,
        }

    def get_user_key_material(self, username: str) -> Optional[Dict[str, Any]]:
        entry = self._user_keys.get(username)
        return json.loads(json.dumps(entry)) if entry else None

    def delete_user_key_material(self, username: str) -> None:
        self._user_keys.pop(username, None)

    # Ledger-Transaktionen -----------------------------------------------
    def append_ledger_transaction(self, txn: Dict[str, Any]) -> None:
        txn_id = str(txn.get("transactionId") or "").strip()
        if not txn_id:
            raise ValueError("transactionId fehlt")
        if txn_id in self._ledger_transactions:
            raise ValueError("Transaktion existiert bereits")
        self._ledger_transactions[txn_id] = json.loads(json.dumps(txn))
        self._ledger_order.append(txn_id)

    def upsert_ledger_transaction(self, txn: Dict[str, Any]) -> None:
        txn_id = str(txn.get("transactionId") or "").strip()
        if not txn_id:
            raise ValueError("transactionId fehlt")
        exists = txn_id in self._ledger_transactions
        self._ledger_transactions[txn_id] = json.loads(json.dumps(txn))
        if not exists:
            self._ledger_order.append(txn_id)

    def get_ledger_transaction(self, txn_id: str) -> Optional[Dict[str, Any]]:
        txn = self._ledger_transactions.get(txn_id)
        return json.loads(json.dumps(txn)) if txn else None

    def list_ledger_transactions(
        self,
        *,
        after_transaction_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        start_index = 0
        if after_transaction_id:
            try:
                start_index = self._ledger_order.index(after_transaction_id) + 1
            except ValueError:
                start_index = 0
        slice_ids = self._ledger_order[start_index : start_index + max(limit, 0)]
        return [json.loads(json.dumps(self._ledger_transactions[txn_id])) for txn_id in slice_ids]

    # Bankinstanzen ------------------------------------------------------
    def register_bank_instance(self, instance_id: str, data: Dict[str, Any]) -> None:
        instance_id = instance_id.strip()
        if not instance_id:
            raise ValueError("instance_id fehlt")
        if instance_id in self._bank_instances:
            raise ValueError("Instanz existiert bereits")
        payload = json.loads(json.dumps(data))
        payload["instanceId"] = instance_id
        self._bank_instances[instance_id] = payload
        self._bank_instance_order.append(instance_id)

    def upsert_bank_instance(self, instance_id: str, data: Dict[str, Any]) -> None:
        instance_id = instance_id.strip()
        if not instance_id:
            raise ValueError("instance_id fehlt")
        payload = json.loads(json.dumps(data))
        payload["instanceId"] = instance_id
        exists = instance_id in self._bank_instances
        self._bank_instances[instance_id] = payload
        if not exists:
            self._bank_instance_order.append(instance_id)

    def get_bank_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        payload = self._bank_instances.get(instance_id)
        return json.loads(json.dumps(payload)) if payload else None

    def list_bank_instances(self) -> List[Dict[str, Any]]:
        return [json.loads(json.dumps(self._bank_instances[iid])) for iid in self._bank_instance_order]

    def delete_bank_instance(self, instance_id: str) -> None:
        if instance_id in self._bank_instances:
            self._bank_instances.pop(instance_id, None)
            try:
                self._bank_instance_order.remove(instance_id)
            except ValueError:
                pass

    # Föderations-Sync-Status -------------------------------------------
    def set_sync_state(self, partner_instance_id: str, data: Dict[str, Any]) -> None:
        partner_instance_id = partner_instance_id.strip()
        if not partner_instance_id:
            raise ValueError("partner_instance_id fehlt")
        self._sync_state[partner_instance_id] = json.loads(json.dumps(data))

    def get_sync_state(self, partner_instance_id: str) -> Optional[Dict[str, Any]]:
        payload = self._sync_state.get(partner_instance_id)
        return json.loads(json.dumps(payload)) if payload else None

    def delete_sync_state(self, partner_instance_id: str) -> None:
        self._sync_state.pop(partner_instance_id, None)

    def list_sync_states(self) -> List[Dict[str, Any]]:
        return [json.loads(json.dumps(payload)) for payload in self._sync_state.values()]


class UpstashStore:
    def __init__(self, client: "UpstashRedis") -> None:
        self._client = client

    # Benutzer-Schlüsselmaterial ----------------------------------------
    def set_user_key_material(
        self,
        username: str,
        *,
        public_key: str,
        encrypted_private_key: Dict[str, Any],
        created_at: str,
    ) -> None:
        if not self.user_exists(username):
            raise KeyError("Benutzer nicht gefunden")
        payload = {
            "publicKey": public_key,
            "encryptedPrivateKey": encrypted_private_key,
            "createdAt": created_at,
        }
        self._client.set(self._user_key_material_key(username), json.dumps(payload))

    def get_user_key_material(self, username: str) -> Optional[Dict[str, Any]]:
        raw = self._client.get(self._user_key_material_key(username))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw)

    def delete_user_key_material(self, username: str) -> None:
        self._client.delete(self._user_key_material_key(username))

    def user_exists(self, username: str) -> bool:
        return bool(self._client.exists(self._user_key(username)))

    def create_user(self, username: str, data: Dict[str, Any]) -> None:
        key = self._user_key(username)
        if self._client.exists(key):
            raise ValueError("Benutzer existiert bereits")
        email = data.get("email")
        iban = data.get("iban")
        if not email or not iban:
            raise ValueError("E-Mail und IBAN werden benötigt")
        email = email.lower()
        iban = iban.upper()
        email_key = self._email_key(email)
        iban_key = self._iban_key(iban)
        if self._client.exists(email_key):
            raise ValueError("E-Mail existiert bereits")
        if self._client.exists(iban_key):
            raise ValueError("IBAN existiert bereits")

        values = data.copy()
        values["email"] = email
        values["iban"] = iban
        self._client.hset(key, values=values)
        self._client.set(email_key, username)
        self._client.set(iban_key, username)

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        data = self._client.hgetall(self._user_key(username))
        if not data:
            return None
        if isinstance(data, list):
            # Upstash kann Listen zurückgeben (alternierende Schlüssel/Werte)
            it = iter(data)
            data = {k: v for k, v in zip(it, it)}
        return data

    def email_exists(self, email: str) -> bool:
        return bool(self._client.exists(self._email_key(email.lower())))

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        username = self.resolve_username_by_email(email)
        if not username:
            return None
        return self.get_user(username)

    def resolve_username_by_email(self, email: str) -> Optional[str]:
        return self._client.get(self._email_key(email.lower()))

    def set_user_field(self, username: str, field: str, value: Any) -> None:
        if not self.user_exists(username):
            raise KeyError("Benutzer nicht gefunden")
        self._client.hset(self._user_key(username), field=field, value=value)

    def update_user_profile(self, username: str, *, first_name: str, last_name: str, email: str) -> None:
        user = self.get_user(username)
        if not user:
            raise KeyError("Benutzer nicht gefunden")

        normalized_email = email.strip().lower()
        if not normalized_email:
            raise ValueError("E-Mail darf nicht leer sein")

        email_key = self._email_key(normalized_email)
        existing = self._client.get(email_key)
        if isinstance(existing, bytes):
            existing = existing.decode()
        if existing and existing != username:
            raise ValueError("E-Mail existiert bereits")

        user_key = self._user_key(username)
        self._client.hset(
            user_key,
            values={
                "first_name": first_name,
                "last_name": last_name,
                "email": normalized_email,
            },
        )

        old_email = str(user.get("email") or "").strip().lower()
        if old_email and old_email != normalized_email:
            self._client.delete(self._email_key(old_email))
        self._client.set(email_key, username)

    def delete_user(self, username: str) -> None:
        user = self.get_user(username)
        if not user:
            raise KeyError("Benutzer nicht gefunden")
        email = str(user.get("email") or "").strip().lower()
        iban = str(user.get("iban") or "").replace(" ", "").upper()
        self._client.delete(self._user_key(username))
        self._client.delete(self._txn_key(username))
        self._client.delete(self._user_key_material_key(username))
        if email:
            self._client.delete(self._email_key(email))
        if iban:
            self._client.delete(self._iban_key(iban))

    def append_transaction(self, username: str, txn: Dict[str, Any]) -> None:
        self._client.lpush(self._txn_key(username), json.dumps(txn))

    def get_transactions(self, username: str) -> List[Dict[str, Any]]:
        raw_items = self._client.lrange(self._txn_key(username), 0, 49) or []
        return [json.loads(item) for item in raw_items]

    def iban_exists(self, iban: str) -> bool:
        return bool(self._client.exists(self._iban_key(iban.upper())))

    def get_user_by_iban(self, iban: str) -> Optional[Dict[str, Any]]:
        username = self.resolve_username_by_iban(iban)
        if not username:
            return None
        return self.get_user(username)

    def resolve_username_by_iban(self, iban: str) -> Optional[str]:
        return self._client.get(self._iban_key(iban.upper()))

    def adjust_balance(self, username: str, delta: Decimal) -> Decimal:
        key = self._user_key(username)
        result = self._client.eval(
            _BALANCE_ADJUST_SCRIPT,
            keys=[key],
            args=[str(delta)],
        )
        if result == "ERR_NOT_FOUND":
            raise KeyError("Benutzer nicht gefunden")
        if result == "ERR_INSUFFICIENT":
            raise ValueError("Unzureichendes Guthaben")
        if isinstance(result, list) and result:
            result = result[0]
        if not isinstance(result, str):
            result = str(result)
        return Decimal(result)

    def save_session(self, token: str, username: str, ttl_seconds: int) -> None:
        key = self._session_key(token)
        self._client.set(key, username, ex=ttl_seconds)

    def get_session(self, token: str) -> Optional[str]:
        return self._client.get(self._session_key(token))

    def delete_session(self, token: str) -> None:
        self._client.delete(self._session_key(token))

    def purge_stale_sessions(self) -> int:
        removed = 0
        try:
            cursor = "0"
            pattern = self._session_key("*")
            while True:
                scan_result = self._client.scan(cursor=cursor, match=pattern, count=48)
                if isinstance(scan_result, (list, tuple)) and len(scan_result) == 2:
                    cursor, keys = scan_result
                else:  # pragma: no cover - defensive handling of client variants
                    break
                if not isinstance(keys, list):
                    keys = []
                for key in keys:
                    token = key.split(":", 1)[1] if isinstance(key, str) and ":" in key else key
                    username = self._client.get(key)
                    ttl = self._client.ttl(key)
                    user_missing = bool(username) and not self.user_exists(str(username))
                    expired = isinstance(ttl, int) and ttl != -1 and ttl <= 0
                    if not username or expired or user_missing:
                        self._client.delete(key)
                        removed += 1
                if cursor in (0, "0", None):
                    break
        except Exception:  # pragma: no cover - Upstash scan may not be available
            return removed
        return removed

    # Ledger-Transaktionen -----------------------------------------------
    def append_ledger_transaction(self, txn: Dict[str, Any]) -> None:
        txn_id = str(txn.get("transactionId") or "").strip()
        if not txn_id:
            raise ValueError("transactionId fehlt")
        txn_key = self._ledger_txn_key(txn_id)
        if self._client.exists(txn_key):
            raise ValueError("Transaktion existiert bereits")
        payload = json.dumps(txn)
        self._client.set(txn_key, payload)
        self._client.rpush(self._ledger_order_key(), txn_id)

    def upsert_ledger_transaction(self, txn: Dict[str, Any]) -> None:
        txn_id = str(txn.get("transactionId") or "").strip()
        if not txn_id:
            raise ValueError("transactionId fehlt")
        txn_key = self._ledger_txn_key(txn_id)
        exists = bool(self._client.exists(txn_key))
        payload = json.dumps(txn)
        self._client.set(txn_key, payload)
        if not exists:
            self._client.rpush(self._ledger_order_key(), txn_id)

    def get_ledger_transaction(self, txn_id: str) -> Optional[Dict[str, Any]]:
        raw = self._client.get(self._ledger_txn_key(txn_id))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw)

    def list_ledger_transactions(
        self,
        *,
        after_transaction_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        order = self._client.lrange(self._ledger_order_key(), 0, -1) or []
        order = [item.decode() if isinstance(item, bytes) else item for item in order]
        start_index = 0
        if after_transaction_id and after_transaction_id in order:
            start_index = order.index(after_transaction_id) + 1
        slice_ids = order[start_index : start_index + max(limit, 0)]
        results: List[Dict[str, Any]] = []
        for txn_id in slice_ids:
            txn = self.get_ledger_transaction(txn_id)
            if txn:
                results.append(txn)
        return results

    # Bankinstanzen ------------------------------------------------------
    def register_bank_instance(self, instance_id: str, data: Dict[str, Any]) -> None:
        instance_id = instance_id.strip()
        if not instance_id:
            raise ValueError("instance_id fehlt")
        key = self._bank_instance_key(instance_id)
        if self._client.exists(key):
            raise ValueError("Instanz existiert bereits")
        payload = data.copy()
        payload["instanceId"] = instance_id
        self._client.set(key, json.dumps(payload))
        self._client.sadd(self._bank_instance_set_key(), instance_id)

    def upsert_bank_instance(self, instance_id: str, data: Dict[str, Any]) -> None:
        instance_id = instance_id.strip()
        if not instance_id:
            raise ValueError("instance_id fehlt")
        key = self._bank_instance_key(instance_id)
        payload = data.copy()
        payload["instanceId"] = instance_id
        self._client.set(key, json.dumps(payload))
        self._client.sadd(self._bank_instance_set_key(), instance_id)

    def get_bank_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        raw = self._client.get(self._bank_instance_key(instance_id))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw)

    def list_bank_instances(self) -> List[Dict[str, Any]]:
        members = self._client.smembers(self._bank_instance_set_key()) or []
        instance_ids = [member.decode() if isinstance(member, bytes) else member for member in members]
        results: List[Dict[str, Any]] = []
        for instance_id in instance_ids:
            data = self.get_bank_instance(instance_id)
            if data:
                results.append(data)
        return results

    def delete_bank_instance(self, instance_id: str) -> None:
        self._client.delete(self._bank_instance_key(instance_id))
        self._client.srem(self._bank_instance_set_key(), instance_id)

    # Föderations-Sync-Status -------------------------------------------
    def set_sync_state(self, partner_instance_id: str, data: Dict[str, Any]) -> None:
        partner_instance_id = partner_instance_id.strip()
        if not partner_instance_id:
            raise ValueError("partner_instance_id fehlt")
        self._client.set(self._sync_state_key(partner_instance_id), json.dumps(data))

    def get_sync_state(self, partner_instance_id: str) -> Optional[Dict[str, Any]]:
        raw = self._client.get(self._sync_state_key(partner_instance_id))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw)

    def delete_sync_state(self, partner_instance_id: str) -> None:
        self._client.delete(self._sync_state_key(partner_instance_id))

    def list_sync_states(self) -> List[Dict[str, Any]]:
        keys = self._client.keys(self._sync_state_key("*")) or []
        results: List[Dict[str, Any]] = []
        for key in keys:
            if isinstance(key, bytes):
                key = key.decode()
            raw = self._client.get(key)
            if not raw:
                continue
            if isinstance(raw, bytes):
                raw = raw.decode()
            results.append(json.loads(raw))
        return results

    @staticmethod
    def _user_key(username: str) -> str:
        return f"user:{username}"

    @staticmethod
    def _txn_key(username: str) -> str:
        return f"transactions:{username}"

    @staticmethod
    def _session_key(token: str) -> str:
        return f"session:{token}"

    @staticmethod
    def _email_key(email: str) -> str:
        return f"email:{email}"

    @staticmethod
    def _iban_key(iban: str) -> str:
        return f"iban:{iban}"

    @staticmethod
    def _user_key_material_key(username: str) -> str:
        return f"user_keys:{username}"

    @staticmethod
    def _ledger_txn_key(txn_id: str) -> str:
        return f"ledger:txn:{txn_id}"

    @staticmethod
    def _ledger_order_key() -> str:
        return "ledger:order"

    @staticmethod
    def _bank_instance_key(instance_id: str) -> str:
        return f"bank:instance:{instance_id}"

    @staticmethod
    def _bank_instance_set_key() -> str:
        return "bank:instances"

    @staticmethod
    def _sync_state_key(partner_instance_id: str) -> str:
        return f"bank:sync:{partner_instance_id}"


def _init_store() -> Any:
    if UpstashRedis is not None:
        rest_url = os.getenv("UPSTASH_REDIS_REST_URL")
        rest_token = os.getenv("UPSTASH_REDIS_REST_TOKEN")
        derived = False

        if (not rest_url or not rest_token) and os.getenv("REDIS_URL"):
            parsed = urlparse(os.getenv("REDIS_URL"))
            if parsed.hostname and parsed.password:
                rest_url = rest_url or f"https://{parsed.hostname}"
                rest_token = rest_token or parsed.password
                derived = True

        if rest_url and rest_token:
            try:
                client = UpstashRedis(url=rest_url, token=rest_token)
                client.ping()
                origin = " (abgeleitet aus REDIS_URL)" if derived else ""
                print(f"Verbunden mit Upstash Redis{origin}")
                return UpstashStore(client)
            except Exception as exc:  # pragma: no cover
                print(f"Upstash-Verbindung fehlgeschlagen ({exc}), verwende MemoryStore")
    return MemoryStore()


store = _init_store()

app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = APP_SECRET


def _apply_logging_configuration() -> None:
    level = logging.DEBUG if app.debug else logging.INFO
    logging.basicConfig(level=level)
    app.logger.setLevel(level)
    logging.getLogger("werkzeug").setLevel(level)


_apply_logging_configuration()


_session_cleanup_timer: Optional[threading.Timer] = None


def _run_session_cleanup() -> None:
    global _session_cleanup_timer
    _session_cleanup_timer = None
    purge = getattr(store, "purge_stale_sessions", None)
    if callable(purge):
        try:
            removed = purge()
            if removed:
                print(f"Session-Bereinigung: {removed} Einträge entfernt.")
        except Exception as exc:  # pragma: no cover - defensive logging
            print(f"Session-Bereinigung fehlgeschlagen: {exc}")
    _schedule_session_cleanup()


def _schedule_session_cleanup() -> None:
    global _session_cleanup_timer
    if SESSION_CLEANUP_INTERVAL_SECONDS <= 0:
        return
    if _session_cleanup_timer is not None:
        return
    timer = threading.Timer(SESSION_CLEANUP_INTERVAL_SECONDS, _run_session_cleanup)
    timer.daemon = True
    _session_cleanup_timer = timer
    timer.start()


def _cancel_session_cleanup() -> None:
    global _session_cleanup_timer
    if _session_cleanup_timer is not None:
        _session_cleanup_timer.cancel()
        _session_cleanup_timer = None


_schedule_session_cleanup()
atexit.register(_cancel_session_cleanup)

_start_ledger_sync()
atexit.register(_stop_ledger_sync)


def _generate_account_id() -> str:
    while True:
        candidate = f"acct_{secrets.token_hex(4)}"
        if not store.user_exists(candidate):
            return candidate


def _compute_iban_check_digits(country_code: str, bban: str) -> str:
    remainder = _iban_mod_97(f"{bban}{country_code}00")
    check_value = 98 - remainder
    if check_value <= 0:
        check_value += 97
    return f"{check_value:02d}"


def _generate_iban() -> str:
    attempts = 0
    while attempts < 20:
        bank_code = f"{secrets.randbelow(10**8):08d}"
        account_number = f"{secrets.randbelow(10**10):010d}"
        bban = f"{bank_code}{account_number}"
        check_digits = _compute_iban_check_digits("DE", bban)
        iban = f"DE{check_digits}{bban}"
        exists = getattr(store, "iban_exists", None)
        if exists is None or not exists(iban):
            return iban
        attempts += 1
    raise RuntimeError("Keine freie IBAN gefunden")


def _hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return {"salt": salt, "password_hash": digest}


def _verify_password(password: str, user: Dict[str, Any]) -> bool:
    salted = _hash_password(password, user.get("salt"))
    return salted["password_hash"] == user.get("password_hash")


def _clean_password(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("Ungültiges Passwort")
    password = raw.strip()
    if len(password) < 6:
        raise ValueError("Passwort muss mindestens 6 Zeichen haben")
    return password


def _require_auth() -> str:
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        token = header[7:].strip()
    else:
        token = None
    if not token:
        raise PermissionError("Kein Token")
    username = store.get_session(token)
    if not username:
        raise PermissionError("Token ungültig oder abgelaufen")
    request.environ["session_token"] = token
    return username


def _require_ledger_token() -> None:
    if not LEDGER_API_TOKEN:
        raise PermissionError("Ledger-API ist deaktiviert")
    provided = request.headers.get("X-Ledger-Token", "").strip()
    if not provided:
        raise PermissionError("Ledger-Token fehlt")
    if not secrets.compare_digest(provided, LEDGER_API_TOKEN):
        raise PermissionError("Ledger-Token ungültig")


def _ledger_error_response(exc: PermissionError):
    message = str(exc)
    status = 401
    if message == "Ledger-API ist deaktiviert":
        status = 503
    return _error(message, status)


def _get_configured_ledger_nodes() -> List[Dict[str, str]]:
    entries = _parse_csv_env(os.getenv("LEDGER_NODE_ADDRESSES"))
    nodes: List[Dict[str, str]] = []
    for entry in entries:
        parsed = _parse_token_and_url(entry, default_token=LEDGER_API_TOKEN)
        if parsed:
            nodes.append(parsed)
    return nodes


def _parse_sync_targets_from_env() -> List[Dict[str, str]]:
    entries = _parse_csv_env(os.getenv("LEDGER_SYNC_TARGETS"))
    targets: List[Dict[str, str]] = []
    for entry in entries:
        parsed = _parse_token_and_url(entry, default_token=LEDGER_API_TOKEN)
        if parsed:
            targets.append(parsed)
    return targets


def _expand_sync_target(target: Dict[str, str]) -> List[Dict[str, str]]:
    base_url = target["base_url"]
    token = target.get("token", LEDGER_API_TOKEN)
    if not base_url:
        return []
    try:
        response = requests.get(
            f"{base_url}/api/ledger/nodes",
            headers=_ledger_headers(token),
            timeout=5,
        )
        if response.status_code != 200:
            return [target]
        payload = response.json()
        nodes = payload.get("nodes", [])
        expanded: List[Dict[str, str]] = []
        for item in nodes:
            parsed: Optional[Dict[str, str]] = None
            if isinstance(item, str):
                parsed = _parse_token_and_url(item, default_token=token)
            elif isinstance(item, dict):
                node_url = str(item.get("baseUrl") or item.get("url") or item.get("host") or "").strip()
                node_token = str(item.get("token") or token or "").strip()
                if node_url:
                    parsed = _parse_token_and_url(
                        f"{node_token}@{node_url}" if node_token else node_url,
                        default_token=token,
                    )
            if parsed:
                expanded.append(parsed)
        return expanded or [target]
    except Exception as exc:  # pragma: no cover - network failures
        LOGGER.debug("Ledger node discovery für %s fehlgeschlagen: %s", base_url, exc)
        return [target]


def _build_sync_targets() -> List[Dict[str, str]]:
    targets: List[Dict[str, str]] = []
    for target in _parse_sync_targets_from_env():
        targets.extend(_expand_sync_target(target))
    unique: Dict[str, Dict[str, str]] = {}
    for item in targets:
        key = item["base_url"]
        if key and key not in unique:
            unique[key] = item
    return list(unique.values())


def _sync_with_target(target: Dict[str, str]) -> None:
    base_url = target["base_url"]
    token = target.get("token", LEDGER_API_TOKEN)
    if not (base_url and token):
        return
    partner_id = base_url
    state = getattr(store, "get_sync_state", None)
    last_synced: Optional[str] = None
    if callable(state):
        current_state = state(partner_id)
        if current_state:
            last_synced = current_state.get("lastTransactionId")

    params: Dict[str, Any] = {"limit": 200}
    if last_synced:
        params["sinceId"] = last_synced

    try:
        response = requests.get(
            f"{base_url}/api/transactions",
            headers=_ledger_headers(token),
            params=params,
            timeout=10,
        )
    except Exception as exc:  # pragma: no cover - network failures
        LOGGER.debug("Ledger Sync zu %s fehlgeschlagen: %s", base_url, exc)
        return

    if response.status_code != 200:
        LOGGER.debug("Ledger Sync zu %s liefert Status %s", base_url, response.status_code)
        return

    try:
        payload = response.json()
    except ValueError:  # pragma: no cover - invalid JSON
        LOGGER.debug("Ledger Sync zu %s lieferte ungültiges JSON", base_url)
        return

    transactions = payload.get("transactions", [])
    if not isinstance(transactions, list):
        return

    latest_id = last_synced
    for entry in transactions:
        if not isinstance(entry, dict):
            continue
        txn_id = str(entry.get("transactionId") or "").strip()
        if not txn_id:
            continue
        latest_id = txn_id
        try:
            store.upsert_ledger_transaction(entry)
        except Exception as exc:  # pragma: no cover - store/backend issues
            LOGGER.debug("Ledger-Eintrag %s konnte nicht gespeichert werden: %s", txn_id, exc)
            continue

    if latest_id and callable(getattr(store, "set_sync_state", None)):
        store.set_sync_state(
            partner_id,
            {
                "lastTransactionId": latest_id,
                "updatedAt": _now_iso(),
            },
        )


def _perform_ledger_sync_cycle() -> None:
    targets = _build_sync_targets()
    if not targets:
        return
    for target in targets:
        _sync_with_target(target)


_ledger_sync_stop_event = threading.Event()
_ledger_sync_thread: Optional[threading.Thread] = None


def _ledger_sync_loop() -> None:  # pragma: no cover - background thread
    interval = max(LEDGER_SYNC_INTERVAL_SECONDS, 15)
    while not _ledger_sync_stop_event.wait(interval):
        _perform_ledger_sync_cycle()


def _start_ledger_sync() -> None:
    global _ledger_sync_thread
    if _ledger_sync_thread is not None:
        return
    if LEDGER_SYNC_INTERVAL_SECONDS <= 0:
        return
    if not os.getenv("LEDGER_SYNC_TARGETS", "").strip():
        return
    _ledger_sync_stop_event.clear()
    _perform_ledger_sync_cycle()
    thread = threading.Thread(target=_ledger_sync_loop, name="ledger-sync", daemon=True)
    _ledger_sync_thread = thread
    thread.start()


def _stop_ledger_sync() -> None:
    global _ledger_sync_thread
    if _ledger_sync_thread is None:
        return
    _ledger_sync_stop_event.set()
    _ledger_sync_thread.join(timeout=5)
    _ledger_sync_thread = None


def _issue_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    store.save_session(token, username, SESSION_TTL_SECONDS)
    return token


def _get_user_key_material(username: str) -> Optional[Dict[str, Any]]:
    getter = getattr(store, "get_user_key_material", None)
    if callable(getter):
        return getter(username)
    return None


def _set_user_key_material(
    username: str,
    *,
    public_key: str,
    encrypted_private_key: Dict[str, Any],
    created_at: str,
) -> None:
    setter = getattr(store, "set_user_key_material", None)
    if not callable(setter):
        raise RuntimeError("Schlüsselverwaltung nicht verfügbar")
    setter(
        username,
        public_key=public_key,
        encrypted_private_key=encrypted_private_key,
        created_at=created_at,
    )

def _delete_user_key_material(username: str) -> None:
    deleter = getattr(store, "delete_user_key_material", None)
    if callable(deleter):
        deleter(username)


def _issue_user_keypair(username: str, password: str, *, expose_private: bool = False) -> Dict[str, Any]:
    keypair = generate_user_keypair()
    encrypted = encrypt_private_key(password, keypair.private_key, pepper=USER_KEY_PEPPER)
    created_at = _now_iso()
    material = {
        "publicKey": keypair.public_key_b64(),
        "encryptedPrivateKey": encrypted,
        "createdAt": created_at,
    }
    _set_user_key_material(
        username,
        public_key=material["publicKey"],
        encrypted_private_key=encrypted,
        created_at=created_at,
    )
    if expose_private:
        material["_privateKeyBytes"] = keypair.private_key
    return material


def _ensure_user_key_material(username: str, password: str) -> Optional[Dict[str, Any]]:
    material = _get_user_key_material(username)
    if material:
        return material
    try:
        return _issue_user_keypair(username, password)
    except Exception:
        return None


def _decode_public_key(public_key_b64: str) -> bytes:
    if not isinstance(public_key_b64, str) or not public_key_b64:
        raise ValueError("Öffentlicher Schlüssel fehlt")
    try:
        return base64.b64decode(public_key_b64, validate=True)
    except binascii.Error as exc:
        raise ValueError("Öffentlicher Schlüssel ungültig") from exc


def _build_transaction_message(
    txn_type: str,
    sender_public_key: str,
    receiver_public_key: str,
    amount: str,
    timestamp: str,
) -> bytes:
    payload = {
        "type": txn_type,
        "sender": sender_public_key,
        "receiver": receiver_public_key,
        "amount": amount,
        "timestamp": timestamp,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_transaction_signature(
    txn_type: str,
    sender_public_key: str,
    receiver_public_key: str,
    amount: str,
    timestamp: str,
    signature: str,
) -> bool:
    if not signature or not isinstance(signature, str):
        return False
    try:
        key_bytes = _decode_public_key(sender_public_key)
    except ValueError:
        return False
    message = _build_transaction_message(
        txn_type,
        sender_public_key,
        receiver_public_key,
        amount,
        timestamp,
    )
    return verify_signature_b64(key_bytes, message, signature)


def _generate_transaction_id() -> str:
    return f"txn_{secrets.token_hex(8)}"


def _record_account_transaction(
    username: str,
    txn_type: str,
    amount: Decimal,
    balance: Decimal,
    memo: str,
    *,
    transaction_id: str,
    sender_public_key: str,
    receiver_public_key: str,
    signature: str,
    timestamp: str,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    entry = {
        "transactionId": transaction_id,
        "type": txn_type,
        "amount": _format_amount(amount),
        "balance": _format_amount(balance),
        "createdAt": timestamp,
        "memo": memo,
        "senderPublicKey": sender_public_key,
        "receiverPublicKey": receiver_public_key,
        "signature": signature,
    }
    if extra:
        entry.update(extra)
    store.append_transaction(username, entry)


def _persist_transaction(
    *,
    username: str,
    txn_type: str,
    amount: Decimal,
    balance: Decimal,
    memo: str,
    sender_public_key: str,
    receiver_public_key: str,
    signature: str,
    timestamp: str,
    extra: Optional[Dict[str, Any]] = None,
    transaction_id: Optional[str] = None,
    ledger_amount: Optional[Decimal] = None,
) -> str:
    transaction_id = transaction_id or _generate_transaction_id()
    ledger_value = ledger_amount if ledger_amount is not None else amount.copy_abs()
    ledger_entry = {
        "transactionId": transaction_id,
        "type": txn_type,
        "amount": _format_amount(ledger_value),
        "senderPublicKey": sender_public_key,
        "receiverPublicKey": receiver_public_key,
        "signature": signature,
        "timestamp": timestamp,
    }
    append = getattr(store, "append_ledger_transaction", None)
    if callable(append):
        try:
            append(ledger_entry)
        except ValueError:
            upsert = getattr(store, "upsert_ledger_transaction", None)
            if callable(upsert):
                upsert(ledger_entry)
    _record_account_transaction(
        username,
        txn_type,
        amount,
        balance,
        memo,
        transaction_id=transaction_id,
        sender_public_key=sender_public_key,
        receiver_public_key=receiver_public_key,
        signature=signature,
        timestamp=timestamp,
        extra=extra,
    )
    return transaction_id


def _error(message: str, status: int = 400):
    return jsonify({"error": message}), status


@app.get("/config.js")
def config_js() -> Response:
    debug_flag = "true" if app.debug else "false"
    body = f"window.ALTEBANK_DEBUG = {debug_flag};\n"
    response = Response(body, mimetype="application/javascript")
    if app.debug:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    else:
        response.headers["Cache-Control"] = "public, max-age=300"
    return response


@app.get("/")
def index() -> Any:
    return app.send_static_file("index.html")


@app.get("/api/ledger/nodes")
def ledger_nodes() -> Any:
    try:
        _require_ledger_token()
    except PermissionError as exc:
        return _ledger_error_response(exc)

    nodes_config = _get_configured_ledger_nodes()
    nodes_payload: List[Dict[str, Any]] = []
    for node in nodes_config:
        base_url = node.get("base_url")
        if not base_url:
            continue
        entry: Dict[str, Any] = {"baseUrl": base_url}
        token = node.get("token")
        if token:
            entry["token"] = token
        nodes_payload.append(entry)
    return jsonify({"nodes": nodes_payload})


@app.post("/api/auth/register")
def register() -> Any:
    payload = request.get_json(force=True, silent=True) or {}
    try:
        email = _clean_email(payload.get("email"))
        password = _clean_password(payload.get("password"))
        first_name = _clean_name(payload.get("firstName"), "Vorname")
        last_name = _clean_name(payload.get("lastName"), "Nachname")
        initial = _parse_amount(payload.get("initialDeposit", "0"))
        if initial < Decimal("0"):
            raise ValueError("Initialer Betrag darf nicht negativ sein")
    except ValueError as exc:
        return _error(str(exc))

    email_exists = getattr(store, "email_exists", None)
    if email_exists and email_exists(email):
        return _error("E-Mail existiert bereits", 409)

    credentials = _hash_password(password)
    account_id = _generate_account_id()
    iban = _generate_iban()
    advisor = _pick_random_advisor()
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
            "balance": _format_amount(Decimal("0")),
            "advisor_id": advisor["id"],
        },
    )

    key_material = _issue_user_keypair(account_id, password, expose_private=True)
    private_key_bytes = key_material.pop("_privateKeyBytes", None)

    if initial > Decimal("0"):
        sender_public_key = key_material["publicKey"]
        receiver_public_key = sender_public_key
        timestamp = _now_iso()
        amount_str = _format_amount(initial)
        if private_key_bytes is None:
            try:
                material = _get_user_key_material(account_id)
                if material:
                    private_key_bytes = decrypt_private_key(
                        password,
                        material["encryptedPrivateKey"],
                        pepper=USER_KEY_PEPPER,
                    )
            except DecryptionError:
                private_key_bytes = None
        signature = ""
        if private_key_bytes is not None:
            message = _build_transaction_message(
                "deposit",
                sender_public_key,
                receiver_public_key,
                amount_str,
                timestamp,
            )
            signature = sign_message_b64(private_key_bytes, message)

        new_balance = store.adjust_balance(account_id, initial)
        _persist_transaction(
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

    token = _issue_session(account_id)
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


@app.post("/api/auth/login")
def login() -> Any:
    payload = request.get_json(force=True, silent=True) or {}
    try:
        email = _clean_email(payload.get("email"))
        password = _clean_password(payload.get("password"))
    except ValueError as exc:
        return _error(str(exc))

    user = getattr(store, "get_user_by_email", lambda _: None)(email)
    if not user or not _verify_password(password, user):
        return _error("Ungültige Zugangsdaten", 401)

    account_id = user.get("username")
    if not account_id:
        return _error("Benutzerkonto beschädigt", 500)

    token = _issue_session(account_id)
    key_material = _ensure_user_key_material(account_id, password)
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


@app.post("/api/auth/logout")
def logout() -> Any:
    try:
        username = _require_auth()
        token = request.environ.get("session_token")
        if token:
            store.delete_session(token)
        return jsonify({"success": True, "username": username})
    except PermissionError as exc:
        return _error(str(exc), 401)


@app.put("/api/auth/password")
def update_password() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        current_password = _clean_password(payload.get("currentPassword"))
        new_password = _clean_password(payload.get("newPassword"))
    except ValueError as exc:
        return _error(str(exc))

    confirm_password = payload.get("confirmPassword")
    if confirm_password is not None:
        confirm_clean = str(confirm_password).strip()
        if confirm_clean != new_password:
            return _error("Neue Passwörter stimmen nicht überein")

    user = store.get_user(username)
    if not user:
        return _error("Benutzer nicht gefunden", 404)

    if not _verify_password(current_password, user):
        return _error("Aktuelles Passwort ist falsch", 400)

    credentials = _hash_password(new_password)
    try:
        store.set_user_field(username, "salt", credentials["salt"])
        store.set_user_field(username, "password_hash", credentials["password_hash"])
    except KeyError as exc:
        return _error(str(exc), 404)

    key_material = _get_user_key_material(username)
    if key_material:
        try:
            private_key_bytes = decrypt_private_key(
                current_password,
                key_material["encryptedPrivateKey"],
                pepper=USER_KEY_PEPPER,
            )
        except DecryptionError:
            return _error("Schlüssel konnte nicht entschlüsselt werden", 500)

        new_payload = encrypt_private_key(
            new_password,
            private_key_bytes,
            pepper=USER_KEY_PEPPER,
        )
        _set_user_key_material(
            username,
            public_key=key_material["publicKey"],
            encrypted_private_key=new_payload,
            created_at=_now_iso(),
        )
    else:
        _ensure_user_key_material(username, new_password)

    return jsonify({"success": True})


@app.get("/api/user/keypair")
def user_keypair_get() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    material = _get_user_key_material(username)
    if not material:
        return _error("Schlüsselmaterial nicht gefunden", 404)

    return jsonify(
        {
            "publicKey": material.get("publicKey"),
            "createdAt": material.get("createdAt"),
            "encryptedPrivateKey": material.get("encryptedPrivateKey"),
        }
    )


@app.post("/api/user/keypair")
def user_keypair_rotate() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        data = _KEYPAIR_ROTATE_SCHEMA.load(payload)
    except ValidationError as exc:
        return _error(_validation_error_message(exc))

    user = store.get_user(username)
    if not user:
        return _error("Benutzer nicht gefunden", 404)
    if not _verify_password(data["password"], user):
        return _error("Passwort ist falsch", 400)

    previous_material = _get_user_key_material(username)

    keypair = generate_user_keypair()
    encrypted = encrypt_private_key(
        data["password"],
        keypair.private_key,
        pepper=USER_KEY_PEPPER,
    )
    created_at = _now_iso()
    _set_user_key_material(
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


@app.delete("/api/user/keypair")
def user_keypair_delete() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        data = _KEYPAIR_DELETE_SCHEMA.load(payload)
    except ValidationError as exc:
        return _error(_validation_error_message(exc))

    user = store.get_user(username)
    if not user:
        return _error("Benutzer nicht gefunden", 404)
    if not _verify_password(data["password"], user):
        return _error("Passwort ist falsch", 400)

    material = _get_user_key_material(username)
    if not material:
        return _error("Schlüsselmaterial nicht gefunden", 404)

    _delete_user_key_material(username)

    return jsonify({
        "success": True,
        "revokedPublicKey": material.get("publicKey"),
    })


@app.get("/api/accounts/me")
def account_me() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    user = store.get_user(username)
    if not user:
        return _error("Benutzer nicht gefunden", 404)

    txns = store.get_transactions(username)
    advisor_id = user.get("advisor_id")
    if not advisor_id:
        advisor_profile = _pick_random_advisor()
        try:
            store.set_user_field(username, "advisor_id", advisor_profile["id"])
        except Exception:
            pass
    else:
        advisor_profile = _get_advisor_by_id(str(advisor_id))
    key_material = _get_user_key_material(username)
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
            "bankPublicKey": BANK_PUBLIC_KEY,
        }
    )


@app.put("/api/accounts/me")
def account_update() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        first_name = _clean_name(payload.get("firstName"), "Vorname")
        last_name = _clean_name(payload.get("lastName"), "Nachname")
        email = _clean_email(payload.get("email"))
    except ValueError as exc:
        return _error(str(exc))

    updater = getattr(store, "update_user_profile", None)
    if not callable(updater):  # pragma: no cover - alle Stores sollten dies unterstützen
        return _error("Profilaktualisierung derzeit nicht möglich", 500)

    try:
        updater(
            username,
            first_name=first_name,
            last_name=last_name,
            email=email,
        )
    except KeyError:
        return _error("Benutzer nicht gefunden", 404)
    except ValueError as exc:
        message = str(exc)
        status = 409 if "existiert" in message else 400
        return _error(message, status)

    return jsonify({"success": True})


@app.delete("/api/accounts/me")
def account_delete() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        confirm_iban = _clean_iban(payload.get("confirmIban"))
    except ValueError as exc:
        return _error(str(exc))

    user = store.get_user(username)
    if not user:
        return _error("Benutzer nicht gefunden", 404)

    stored_iban = str(user.get("iban") or "").replace(" ", "").upper()
    if not stored_iban:
        return _error("IBAN fehlt für dieses Konto", 400)
    if confirm_iban != stored_iban:
        return _error("IBAN stimmt nicht überein", 400)

    deleter = getattr(store, "delete_user", None)
    if deleter is None:
        return _error("Kontolöschung derzeit nicht möglich", 500)

    try:
        deleter(username)
    except KeyError as exc:
        return _error(str(exc), 404)

    token = request.environ.get("session_token")
    if token:
        store.delete_session(token)

    _delete_user_key_material(username)

    return jsonify({"success": True})


@app.post("/api/accounts/deposit")
def account_deposit() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        amount = _parse_amount(payload.get("amount"))
        if amount <= Decimal("0"):
            raise ValueError("Betrag muss positiv sein")
    except ValueError as exc:
        return _error(str(exc))

    timestamp_raw = payload.get("timestamp")
    if not isinstance(timestamp_raw, str) or not timestamp_raw.strip():
        return _error("Zeitstempel fehlt")
    timestamp = timestamp_raw.strip()

    signature_raw = payload.get("signature")
    if not isinstance(signature_raw, str) or not signature_raw.strip():
        return _error("Signatur fehlt")
    signature = signature_raw.strip()

    key_material = _get_user_key_material(username)
    if not key_material:
        return _error("Schlüsselmaterial nicht gefunden", 500)

    sender_public_key = key_material.get("publicKey")
    receiver_public_key = sender_public_key
    amount_str = _format_amount(amount.copy_abs())

    if not _verify_transaction_signature(
        "deposit",
        sender_public_key,
        receiver_public_key,
        amount_str,
        timestamp,
        signature,
    ):
        return _error("Signatur ungültig", 400)

    try:
        balance = store.adjust_balance(username, amount)
    except (KeyError, ValueError) as exc:
        return _error(str(exc), 400)

    transaction_id = _persist_transaction(
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
    return jsonify({"balance": _format_amount(balance), "transactionId": transaction_id})


@app.post("/api/accounts/withdraw")
def account_withdraw() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        amount = _parse_amount(payload.get("amount"))
        if amount <= Decimal("0"):
            raise ValueError("Betrag muss positiv sein")
    except ValueError as exc:
        return _error(str(exc))

    timestamp_raw = payload.get("timestamp")
    if not isinstance(timestamp_raw, str) or not timestamp_raw.strip():
        return _error("Zeitstempel fehlt")
    timestamp = timestamp_raw.strip()

    signature_raw = payload.get("signature")
    if not isinstance(signature_raw, str) or not signature_raw.strip():
        return _error("Signatur fehlt")
    signature = signature_raw.strip()

    key_material = _get_user_key_material(username)
    if not key_material:
        return _error("Schlüsselmaterial nicht gefunden", 500)

    sender_public_key = key_material.get("publicKey")
    receiver_public_key = BANK_PUBLIC_KEY
    amount_str = _format_amount(amount.copy_abs())

    if not _verify_transaction_signature(
        "withdraw",
        sender_public_key,
        receiver_public_key,
        amount_str,
        timestamp,
        signature,
    ):
        return _error("Signatur ungültig", 400)

    try:
        balance = store.adjust_balance(username, -amount)
    except ValueError as exc:
        return _error(str(exc), 400)
    except KeyError as exc:
        return _error(str(exc), 404)

    transaction_id = _persist_transaction(
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
    return jsonify({"balance": _format_amount(balance), "transactionId": transaction_id})


@app.post("/api/accounts/transfer")
def account_transfer() -> Any:
    try:
        username = _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        target_iban = _clean_iban(payload.get("targetIban"))
        target_first = _clean_name(payload.get("targetFirstName"), "Empfänger-Vorname")
        target_last = _clean_name(payload.get("targetLastName"), "Empfänger-Nachname")
        amount = _parse_amount(payload.get("amount"))
        if amount <= Decimal("0"):
            raise ValueError("Betrag muss positiv sein")
    except ValueError as exc:
        return _error(str(exc))

    timestamp_raw = payload.get("timestamp")
    if not isinstance(timestamp_raw, str) or not timestamp_raw.strip():
        return _error("Zeitstempel fehlt")
    timestamp = timestamp_raw.strip()

    signature_raw = payload.get("signature")
    if not isinstance(signature_raw, str) or not signature_raw.strip():
        return _error("Signatur fehlt")
    signature = signature_raw.strip()

    source_user = store.get_user(username)
    if not source_user:
        return _error("Benutzer nicht gefunden", 404)

    key_material = _get_user_key_material(username)
    if not key_material:
        return _error("Schlüsselmaterial nicht gefunden", 500)
    sender_public_key = key_material.get("publicKey")

    resolve_by_iban = getattr(store, "get_user_by_iban", None)
    if resolve_by_iban is None:
        return _error("Überweisungen sind derzeit nicht möglich", 500)

    target_user = resolve_by_iban(target_iban)
    if not target_user:
        return _error("Zielkonto existiert nicht", 404)

    target_username = target_user.get("username")
    if not target_username:
        return _error("Zielkonto konnte nicht geladen werden", 500)

    if target_username == username:
        return _error("Zielkonto muss abweichen")

    stored_first = (target_user.get("first_name") or "").strip().casefold()
    stored_last = (target_user.get("last_name") or "").strip().casefold()
    stored_iban = (target_user.get("iban") or "").replace(" ", "").upper()
    if stored_iban != target_iban:
        return _error("IBAN konnte nicht bestätigt werden")
    if stored_first != target_first.casefold() or stored_last != target_last.casefold():
        return _error("Empfängerdaten stimmen nicht mit der IBAN überein")

    target_key_material = _get_user_key_material(target_username)
    if not target_key_material:
        return _error("Empfänger besitzt kein Schlüsselmaterial", 500)

    receiver_public_key = target_key_material.get("publicKey")
    amount_str = _format_amount(amount.copy_abs())

    if not _verify_transaction_signature(
        "transfer",
        sender_public_key,
        receiver_public_key,
        amount_str,
        timestamp,
        signature,
    ):
        return _error("Signatur ungültig", 400)

    try:
        source_balance = store.adjust_balance(username, -amount)
    except ValueError as exc:
        return _error(str(exc), 400)
    except KeyError as exc:
        return _error(str(exc), 404)

    target_balance = store.adjust_balance(target_username, amount)

    source_first = (source_user.get("first_name") or "").strip()
    source_last = (source_user.get("last_name") or "").strip()
    source_iban = (source_user.get("iban") or "").strip()

    transaction_id = _generate_transaction_id()

    _persist_transaction(
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
    _record_account_transaction(
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

    return jsonify({"balance": _format_amount(source_balance), "transactionId": transaction_id})


@app.post("/api/accounts/resolve")
def account_resolve() -> Any:
    try:
        _require_auth()
    except PermissionError as exc:
        return _error(str(exc), 401)

    payload = request.get_json(force=True, silent=True) or {}
    try:
        target_iban = _clean_iban(payload.get("targetIban"))
    except ValueError as exc:
        return _error(str(exc))

    resolve_by_iban = getattr(store, "get_user_by_iban", None)
    if resolve_by_iban is None:
        return _error("Auflösung nicht verfügbar", 500)

    target_user = resolve_by_iban(target_iban)
    if not target_user:
        return _error("Konto nicht gefunden", 404)

    username = target_user.get("username")
    if not username:
        return _error("Konto beschädigt", 500)

    key_material = _get_user_key_material(username)
    return jsonify(
        {
            "accountId": username,
            "firstName": target_user.get("first_name"),
            "lastName": target_user.get("last_name"),
            "publicKey": key_material.get("publicKey") if key_material else None,
            "keyCreatedAt": key_material.get("createdAt") if key_material else None,
        }
    )


@app.get("/api/transactions")
def transactions_admin_list() -> Any:
    try:
        _require_ledger_token()
    except PermissionError as exc:
        return _ledger_error_response(exc)

    try:
        params = _TRANSACTIONS_QUERY_SCHEMA.load(request.args)
    except ValidationError as exc:
        return _error(_validation_error_message(exc))

    partner = params.get("partner")
    limit = params.get("limit", 100)
    since_id = params.get("since_id")

    collected: List[Dict[str, Any]] = []
    cursor = since_id
    batch_size = max(limit, 50)
    safety = 0

    while len(collected) < limit:
        batch = store.list_ledger_transactions(after_transaction_id=cursor, limit=batch_size)
        if not batch:
            break
        cursor = batch[-1].get("transactionId") or cursor
        for entry in batch:
            if partner:
                if entry.get("senderPublicKey") != partner and entry.get("receiverPublicKey") != partner:
                    continue
            collected.append(entry)
            if len(collected) >= limit:
                break
        if len(batch) < batch_size:
            break
        safety += 1
        if safety >= 32 or cursor is None:
            break

    body: Dict[str, Any] = {"transactions": collected}
    if collected and len(collected) == limit:
        last_id = collected[-1].get("transactionId")
        if last_id:
            body["nextSinceId"] = last_id
    return jsonify(body)


@app.post("/api/transactions")
def transactions_admin_inject() -> Any:
    try:
        _require_ledger_token()
    except PermissionError as exc:
        return _ledger_error_response(exc)

    return _error("Ledger kann nur gelesen werden", 405)


@app.get("/api/transactions/verify/<string:transaction_id>")
def transactions_admin_verify(transaction_id: str) -> Any:
    try:
        _require_ledger_token()
    except PermissionError as exc:
        return _ledger_error_response(exc)

    getter = getattr(store, "get_ledger_transaction", None)
    if not callable(getter):
        return _error("Ledger-Speicher nicht verfügbar", 503)

    record = getter(transaction_id)
    if not record:
        return _error("Transaktion nicht gefunden", 404)

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

    verified = _verify_transaction_signature(
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
        "ledgerEntry": record,
    }
    if not verified:
        response_body["reason"] = "Signatur ungültig"
    return jsonify(response_body)


@app.errorhandler(404)
def not_found(_: Exception) -> Any:  # pragma: no cover
    if request.path.startswith("/api/"):
        return _error("Ressource nicht gefunden", 404)
    return app.send_static_file("index.html")


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    debug_env = os.getenv("FLASK_DEBUG")
    debug = False
    if debug_env is not None:
        debug = debug_env.lower() not in {"0", "false", "off"}
    elif os.getenv("FLASK_ENV", "").lower() == "development":
        debug = True

    app.debug = debug
    _apply_logging_configuration()
    app.run(host="0.0.0.0", port=port, debug=debug)