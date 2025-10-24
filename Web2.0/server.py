"""Flask-Anwendung für das Web2.0-Banking-Demo."""

import atexit
import hashlib
import json
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, jsonify, request

try:
    from upstash_redis import Redis as UpstashRedis
except ModuleNotFoundError:  # pragma: no cover
    UpstashRedis = None


load_dotenv()

APP_SECRET = os.getenv("APP_SECRET_KEY", "dev-secret")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "3600"))
SESSION_CLEANUP_INTERVAL_SECONDS = int(os.getenv("SESSION_CLEANUP_INTERVAL_SECONDS", "900"))

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
"""


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


class MemoryStore:
    """Einfacher Fallback, falls keine Redis-Verbindung verfügbar ist."""

    def __init__(self) -> None:
        self._users: Dict[str, Dict[str, Any]] = {}
        self._transactions: Dict[str, List[Dict[str, Any]]] = {}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._email_index: Dict[str, str] = {}
        self._iban_index: Dict[str, str] = {}

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

    def delete_user(self, username: str) -> None:
        if username not in self._users:
            raise KeyError("Benutzer nicht gefunden")
        user = self._users.pop(username)
        self._transactions.pop(username, None)
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


class UpstashStore:
    def __init__(self, client: "UpstashRedis") -> None:
        self._client = client

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

    def delete_user(self, username: str) -> None:
        user = self.get_user(username)
        if not user:
            raise KeyError("Benutzer nicht gefunden")
        email = str(user.get("email") or "").strip().lower()
        iban = str(user.get("iban") or "").replace(" ", "").upper()
        self._client.delete(self._user_key(username))
        self._client.delete(self._txn_key(username))
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


def _issue_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    store.save_session(token, username, SESSION_TTL_SECONDS)
    return token


def _error(message: str, status: int = 400):
    return jsonify({"error": message}), status


@app.get("/")
def index() -> Any:
    return app.send_static_file("index.html")


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

    if initial > Decimal("0"):
        new_balance = store.adjust_balance(account_id, initial)
        store.append_transaction(
            account_id,
            {
                "type": "deposit",
                "amount": _format_amount(initial),
                "balance": _format_amount(new_balance),
                "createdAt": _now_iso(),
                "memo": "Initiale Einzahlung",
            },
        )

    token = _issue_session(account_id)
    return jsonify(
        {
            "token": token,
            "firstName": first_name,
            "lastName": last_name,
            "iban": iban,
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
    return jsonify(
        {
            "token": token,
            "firstName": user.get("first_name"),
            "lastName": user.get("last_name"),
            "iban": user.get("iban"),
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

    return jsonify({"success": True})


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
        }
    )


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

    return jsonify({"success": True})


def _record_transaction(
    username: str,
    txn_type: str,
    amount: Decimal,
    balance: Decimal,
    memo: str,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    entry = {
        "type": txn_type,
        "amount": _format_amount(amount),
        "balance": _format_amount(balance),
        "createdAt": _now_iso(),
        "memo": memo,
    }
    if extra:
        entry.update(extra)
    store.append_transaction(username, entry)


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

    try:
        balance = store.adjust_balance(username, amount)
    except (KeyError, ValueError) as exc:
        return _error(str(exc), 400)

    _record_transaction(username, "deposit", amount, balance, "Einzahlung")
    return jsonify({"balance": _format_amount(balance)})


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

    try:
        balance = store.adjust_balance(username, -amount)
    except ValueError as exc:
        return _error(str(exc), 400)
    except KeyError as exc:
        return _error(str(exc), 404)

    _record_transaction(username, "withdraw", -amount, balance, "Auszahlung")
    return jsonify({"balance": _format_amount(balance)})


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

    source_user = store.get_user(username)
    if not source_user:
        return _error("Benutzer nicht gefunden", 404)

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

    _record_transaction(
        username,
        "transfer_out",
        -amount,
        source_balance,
        f"Überweisung an {target_first} {target_last}",
        {
            "counterpartyIban": target_iban,
            "counterpartyName": f"{target_first} {target_last}".strip(),
        },
    )
    _record_transaction(
        target_username,
        "transfer_in",
        amount,
        target_balance,
        f"Überweisung von {source_first} {source_last}",
        {
            "counterpartyIban": source_iban,
            "counterpartyName": f"{source_first} {source_last}".strip(),
        },
    )

    return jsonify({"balance": _format_amount(source_balance)})


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

    app.run(host="0.0.0.0", port=port, debug=debug)