"""Flask-Anwendung für das Web3.0-Banking-Demo."""

import atexit
import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse, urlsplit

import requests
from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request
from marshmallow import Schema, ValidationError, fields, validate

from libaries.api import register_apis

from libaries.crypto_utils import (
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


class _StoreProxy:
    """Late-binding proxy so blueprints always talk to the active store."""

    def __getattr__(self, item):
        return getattr(globals()["store"], item)

    def __setattr__(self, key, value):
        setattr(globals()["store"], key, value)


_STORE_PROXY = _StoreProxy()


class ApiContext(SimpleNamespace):
    """Provides blueprint helpers with the current store instance."""

    @property
    def store(self):  # type: ignore[override]
        return _STORE_PROXY

APP_SECRET = os.getenv("APP_SECRET_KEY") or secrets.token_hex(32)
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
SESSION_CLEANUP_INTERVAL_SECONDS = int(os.getenv("SESSION_CLEANUP_INTERVAL_SECONDS", "600"))

LEDGER_API_TOKEN = os.getenv("LEDGER_API_TOKEN", "").strip()
AUTH_TRANS_TOKEN = os.getenv("AUTH_TRANS_TOKEN", "").strip()

FQDN_ALTEBANK = os.getenv("FQDN_ALTEBANK", "").strip().lower()
CONTROL_BASE_URL = os.getenv("CONTROL_BASE_URL", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip()
INSTANCE_ID = os.getenv("INSTANCE_ID", os.getenv("HOSTNAME", "node_" + secrets.token_hex(4))).strip()

LEDGER_SYNC_INTERVAL_SECONDS = int(os.getenv("LEDGER_SYNC_INTERVAL_SECONDS", "60"))
INSTANCE_HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("INSTANCE_HEARTBEAT_INTERVAL_SECONDS", "120"))
INSTANCE_STALE_THRESHOLD_SECONDS = int(os.getenv("INSTANCE_STALE_THRESHOLD_SECONDS", str(10 * 60)))
INSTANCE_STALE_GRACE_SECONDS = int(os.getenv("INSTANCE_STALE_GRACE_SECONDS", str(5 * 60)))
CONTROL_HEALTH_INTERVAL_SECONDS = int(os.getenv("CONTROL_HEALTH_INTERVAL_SECONDS", "60"))

user_key_pepper_raw = os.getenv("USER_KEY_ENC_SECRET", "").strip()
USER_KEY_PEPPER: Optional[bytes] = user_key_pepper_raw.encode("utf-8") if user_key_pepper_raw else None

BANK_PUBLIC_KEY = os.getenv("BANK_PUBLIC_KEY", "BANK_SYSTEM").strip()
BANK_NAME = os.getenv("BANK_NAME", "AlteBank Web3.0").strip() or "AlteBank Web3.0"

_EXTERNAL_IP_LOOKUP_ENDPOINTS = [endpoint.strip() for endpoint in os.getenv(
    "EXTERNAL_IP_LOOKUP_ENDPOINTS",
    "https://api.ipify.org,https://ifconfig.me/ip",
).split(",") if endpoint.strip()]

SERVER_EXTERNAL_IP: Optional[str] = None
SERVER_ROLE: str = "control"
SERVER_BASE_URL: Optional[str] = None
CONTROL_SERVER_BASE_URL: Optional[str] = None
FAILED_NODE_CHECKS: Dict[str, datetime] = {}

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


def _auth_trans_headers(token: str) -> Dict[str, str]:
    return {"X-Auth-Trans-Token": token} if token else {}


def _determine_external_ip() -> Optional[str]:
    for endpoint in _EXTERNAL_IP_LOOKUP_ENDPOINTS:
        try:
            response = requests.get(endpoint, timeout=5)
            if response.status_code == 200:
                candidate = response.text.strip()
                if candidate:
                    return candidate
        except requests.RequestException:
            continue
    return None


def _resolve_fqdn_ips(fqdn: str) -> Set[str]:
    ips: Set[str] = set()
    if not fqdn:
        return ips
    try:
        addr_info = socket.getaddrinfo(fqdn, None)
    except socket.gaierror:
        return ips
    for info in addr_info:
        if len(info) >= 5:
            host = info[4][0]
            if host:
                ips.add(host)
    return ips


def _ip_matches(candidate: str, targets: Iterable[str]) -> bool:
    try:
        cand_ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    for target in targets:
        try:
            if cand_ip == ipaddress.ip_address(target):
                return True
        except ValueError:
            continue
    return False


def _normalize_base_url(url: str, default_scheme: str = "https") -> str:
    if not url:
        raise ValueError("URL darf nicht leer sein")
    parsed = urlsplit(url if "://" in url else f"{default_scheme}://{url}")
    scheme = parsed.scheme or default_scheme
    netloc = parsed.netloc or parsed.path
    path = parsed.path if parsed.netloc else ""
    if not netloc:
        raise ValueError("Ungültige URL")
    normalized = f"{scheme}://{netloc}"
    if path and path != "/":
        normalized = f"{normalized}{path.rstrip('/')}"
    return normalized.rstrip("/")


def _build_default_base_url(external_ip: Optional[str]) -> str:
    scheme = os.getenv("PUBLIC_BASE_SCHEME", "https").strip() or "https"
    port = os.getenv("PUBLIC_PORT", os.getenv("PORT", "8000")).strip()
    host = os.getenv("PUBLIC_HOST", external_ip or "127.0.0.1")
    if not host:
        host = "127.0.0.1"
    default_ports = {"http": "80", "https": "443"}
    include_port = port and port not in (default_ports.get(scheme), "")
    netloc = f"{host}:{port}" if include_port else host
    return f"{scheme}://{netloc}".rstrip("/")


def _determine_server_role() -> None:
    global SERVER_EXTERNAL_IP, SERVER_ROLE, SERVER_BASE_URL, CONTROL_SERVER_BASE_URL

    if not FQDN_ALTEBANK:
        SERVER_ROLE = "control"
        SERVER_EXTERNAL_IP = os.getenv("EXTERNAL_IP_OVERRIDE", "127.0.0.1")
        SERVER_BASE_URL = _normalize_base_url(PUBLIC_BASE_URL or _build_default_base_url(SERVER_EXTERNAL_IP), default_scheme="http")
        CONTROL_SERVER_BASE_URL = SERVER_BASE_URL
        return

    external_ip = _determine_external_ip()
    if not external_ip:
        raise SystemExit("Öffentliche IP-Adresse konnte nicht ermittelt werden. Bitte Internetzugang prüfen.")

    resolved_ips = _resolve_fqdn_ips(FQDN_ALTEBANK)
    SERVER_EXTERNAL_IP = external_ip

    is_control = _ip_matches(external_ip, resolved_ips)
    SERVER_ROLE = "control" if is_control else "member"

    base_url_candidate = PUBLIC_BASE_URL or _build_default_base_url(external_ip)
    try:
        SERVER_BASE_URL = _normalize_base_url(base_url_candidate)
    except ValueError:
        SERVER_BASE_URL = _build_default_base_url(external_ip)

    if CONTROL_BASE_URL:
        try:
            CONTROL_SERVER_BASE_URL = _normalize_base_url(CONTROL_BASE_URL)
        except ValueError:
            CONTROL_SERVER_BASE_URL = f"https://{FQDN_ALTEBANK}"
    else:
        CONTROL_SERVER_BASE_URL = f"https://{FQDN_ALTEBANK}"

    if SERVER_ROLE == "control":
        CONTROL_SERVER_BASE_URL = SERVER_BASE_URL


try:
    _determine_server_role()
except SystemExit:
    raise
except Exception as exc:  # pragma: no cover - defensive bootstrap
    print(f"Cluster-Rollenzuordnung fehlgeschlagen: {exc}")
    raise SystemExit(1)

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


class _IncomingTransactionSchema(Schema):
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


class _LedgerInstanceRegisterSchema(Schema):
    instance_id = fields.String(required=True, data_key="instanceId", validate=validate.Length(min=3, max=64))
    base_url = fields.String(required=True, data_key="baseUrl")
    public_key = fields.String(load_default=None, data_key="publicKey")
    token = fields.String(load_default=None)
    metadata = fields.Dict(keys=fields.String(), values=fields.Raw(), load_default=None)
    status = fields.String(load_default=None)
    last_seen = fields.String(load_default=None, data_key="lastSeen")


class _LedgerInstanceUpdateSchema(Schema):
    base_url = fields.String(load_default=None, data_key="baseUrl")
    public_key = fields.String(load_default=None, data_key="publicKey")
    token = fields.String(load_default=None)
    metadata = fields.Dict(keys=fields.String(), values=fields.Raw(), load_default=None)
    status = fields.String(load_default=None)
    last_seen = fields.String(load_default=None, data_key="lastSeen")


class _LedgerHeartbeatSchema(Schema):
    status = fields.String(load_default=None)
    metadata = fields.Dict(keys=fields.String(), values=fields.Raw(), load_default=None)


_INCOMING_TRANSACTION_SCHEMA = _IncomingTransactionSchema()


_LEDGER_INSTANCE_REGISTER_SCHEMA = _LedgerInstanceRegisterSchema()
_LEDGER_INSTANCE_UPDATE_SCHEMA = _LedgerInstanceUpdateSchema()
_LEDGER_HEARTBEAT_SCHEMA = _LedgerHeartbeatSchema()


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
        self._public_key_index: Dict[str, str] = {}

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

    def get_user_by_public_key(self, public_key: str) -> Optional[Dict[str, Any]]:
        username = self.resolve_username_by_public_key(public_key)
        if not username:
            return None
        return self.get_user(username)

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
        key_entry = self._user_keys.pop(username, None)
        email = str(user.get("email") or "").strip().lower()
        iban = str(user.get("iban") or "").replace(" ", "").upper()
        if email:
            self._email_index.pop(email, None)
        if iban:
            self._iban_index.pop(iban, None)
        if key_entry and key_entry.get("publicKey"):
            self._public_key_index.pop(str(key_entry["publicKey"]), None)
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
        previous = self._user_keys.get(username)
        if previous and previous.get("publicKey"):
            self._public_key_index.pop(str(previous["publicKey"]), None)
        self._user_keys[username] = {
            "publicKey": public_key,
            "encryptedPrivateKey": json.loads(json.dumps(encrypted_private_key)),
            "createdAt": created_at,
        }
        self._public_key_index[public_key] = username

    def get_user_key_material(self, username: str) -> Optional[Dict[str, Any]]:
        entry = self._user_keys.get(username)
        return json.loads(json.dumps(entry)) if entry else None

    def delete_user_key_material(self, username: str) -> None:
        entry = self._user_keys.pop(username, None)
        if entry and entry.get("publicKey"):
            self._public_key_index.pop(str(entry["publicKey"]), None)

    def resolve_username_by_public_key(self, public_key: str) -> Optional[str]:
        return self._public_key_index.get(public_key)

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
        current = self.get_user_key_material(username)
        if current and current.get("publicKey"):
            self._client.delete(self._public_key_key(str(current["publicKey"])))
        payload = {
            "publicKey": public_key,
            "encryptedPrivateKey": encrypted_private_key,
            "createdAt": created_at,
        }
        self._client.set(self._user_key_material_key(username), json.dumps(payload))
        self._client.set(self._public_key_key(public_key), username)

    def get_user_key_material(self, username: str) -> Optional[Dict[str, Any]]:
        raw = self._client.get(self._user_key_material_key(username))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode()
        return json.loads(raw)

    def delete_user_key_material(self, username: str) -> None:
        material = self.get_user_key_material(username)
        self._client.delete(self._user_key_material_key(username))
        if material and material.get("publicKey"):
            self._client.delete(self._public_key_key(str(material["publicKey"])))

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
        if material and material.get("publicKey"):
            self._client.delete(self._public_key_key(str(material["publicKey"])))

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

    def get_user_by_public_key(self, public_key: str) -> Optional[Dict[str, Any]]:
        username = self.resolve_username_by_public_key(public_key)
        if not username:
            return None
        return self.get_user(username)

    def resolve_username_by_iban(self, iban: str) -> Optional[str]:
        return self._client.get(self._iban_key(iban.upper()))

    def resolve_username_by_public_key(self, public_key: str) -> Optional[str]:
        return self._client.get(self._public_key_key(public_key))

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
    def _public_key_key(public_key: str) -> str:
        return f"public_key:{public_key}"

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

app = Flask(__name__, static_folder="frontend", static_url_path="")
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
    bank_code = "04102025"
    attempts = 0
    while attempts < 50:
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
                material = self.get_user_key_material(username)
                self._client.delete(self._user_key_material_key(username))
                if material and material.get("publicKey"):
                    self._client.delete(self._public_key_key(str(material["publicKey"])))
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


_start_ledger_sync()
atexit.register(_stop_ledger_sync)


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


def _collect_all_ledger_transactions(batch_size: int = 200) -> List[Dict[str, Any]]:
    collected: List[Dict[str, Any]] = []
    cursor: Optional[str] = None
    while True:
        batch = store.list_ledger_transactions(after_transaction_id=cursor, limit=batch_size)
        if not batch:
            break
        collected.extend(batch)
        cursor = batch[-1].get("transactionId")
        if len(batch) < batch_size or not cursor:
            break
    return collected


def _paginate_ledger_transactions(*, since_id: Optional[str], limit: int) -> Dict[str, Any]:
    batch = store.list_ledger_transactions(after_transaction_id=since_id, limit=limit)
    next_cursor: Optional[str] = None
    if batch and len(batch) == limit:
        next_cursor = batch[-1].get("transactionId")
    return {
        "transactions": batch,
        "count": len(batch),
        "nextSinceId": next_cursor,
    }


def _register_api_blueprints() -> None:
    ctx = ApiContext(
        error=_error,
        require_auth=_require_auth,
        require_ledger_token=_require_ledger_token,
        ledger_error_response=_ledger_error_response,
        get_configured_ledger_nodes=_get_configured_ledger_nodes,
        normalize_base_url=_normalize_base_url,
        now_iso=_now_iso,
        validation_error_message=_validation_error_message,
        clean_email=_clean_email,
        clean_password=_clean_password,
        clean_name=_clean_name,
        clean_iban=_clean_iban,
        parse_amount=_parse_amount,
        hash_password=_hash_password,
        generate_account_id=_generate_account_id,
        generate_iban=_generate_iban,
        pick_random_advisor=_pick_random_advisor,
        get_advisor_by_id=_get_advisor_by_id,
        issue_user_keypair=_issue_user_keypair,
        persist_transaction=_persist_transaction,
        record_account_transaction=_record_account_transaction,
        format_amount=_format_amount,
        get_user_key_material=_get_user_key_material,
        ensure_user_key_material=_ensure_user_key_material,
        set_user_key_material=_set_user_key_material,
        delete_user_key_material=_delete_user_key_material,
        verify_password=_verify_password,
        issue_session=_issue_session,
        user_key_pepper=USER_KEY_PEPPER,
        decrypt_private_key=decrypt_private_key,
        encrypt_private_key=encrypt_private_key,
        sign_message_b64=sign_message_b64,
        build_transaction_message=_build_transaction_message,
        decryption_error=DecryptionError,
        generate_user_keypair=generate_user_keypair,
        verify_transaction_signature=_verify_transaction_signature,
        generate_transaction_id=_generate_transaction_id,
        bank_public_key=BANK_PUBLIC_KEY,
        collect_all_ledger_transactions=_collect_all_ledger_transactions,
        paginate_ledger_transactions=_paginate_ledger_transactions,
        incoming_transaction_schema=_INCOMING_TRANSACTION_SCHEMA,
        bank_name=BANK_NAME,
    )
    register_apis(app, ctx)


_register_api_blueprints()


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