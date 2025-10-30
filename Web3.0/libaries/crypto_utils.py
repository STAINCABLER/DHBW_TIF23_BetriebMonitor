"""Hilfsfunktionen für Schlüsselverwaltung und Signaturen."""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from typing import Dict, Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ARGON_TIME_COST = 3
_ARGON_MEMORY_COST = 64 * 1024
_ARGON_PARALLELISM = 4
_ARGON_HASH_LEN = 32
_SALT_LEN = 16
_NONCE_LEN = 12


class CryptoError(Exception):
    """Allgemeine Kryptografie-Fehler."""


class DecryptionError(CryptoError):
    """Privater Schlüssel konnte nicht entschlüsselt werden."""


class SignatureError(CryptoError):
    """Signaturprüfung fehlgeschlagen."""


@dataclass(frozen=True)
class KeyPair:
    """Container für ein Ed25519-Schlüsselpaar."""

    private_key: bytes
    public_key: bytes

    def public_key_b64(self) -> str:
        return _encode_b64(self.public_key)

    def private_key_b64(self) -> str:
        return _encode_b64(self.private_key)


def generate_user_keypair() -> KeyPair:
    private = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return KeyPair(private_key=private_bytes, public_key=public_bytes)


def encrypt_private_key(
    password: str,
    private_key: bytes,
    *,
    pepper: Optional[bytes] = None,
) -> Dict[str, object]:
    salt = os.urandom(_SALT_LEN)
    derived_key = _derive_key(password, pepper, salt=salt)
    nonce = os.urandom(_NONCE_LEN)
    aes = AESGCM(derived_key)
    ciphertext = aes.encrypt(nonce, private_key, None)
    return {
        "version": 1,
        "kdf": {
            "algorithm": "argon2id",
            "timeCost": _ARGON_TIME_COST,
            "memoryCost": _ARGON_MEMORY_COST,
            "parallelism": _ARGON_PARALLELISM,
            "hashLen": _ARGON_HASH_LEN,
        },
        "salt": _encode_b64(salt),
        "nonce": _encode_b64(nonce),
        "ciphertext": _encode_b64(ciphertext),
    }


def decrypt_private_key(
    password: str,
    payload: Dict[str, object],
    *,
    pepper: Optional[bytes] = None,
) -> bytes:
    version = int(payload.get("version", 0))
    if version != 1:
        raise DecryptionError("Unbekannte Schlüsselversion")

    salt_b64 = payload.get("salt")
    nonce_b64 = payload.get("nonce")
    ciphertext_b64 = payload.get("ciphertext")

    if not isinstance(salt_b64, str) or not isinstance(nonce_b64, str) or not isinstance(ciphertext_b64, str):
        raise DecryptionError("Schlüsselmaterial unvollständig")

    try:
        salt = _decode_b64(salt_b64)
        nonce = _decode_b64(nonce_b64)
        ciphertext = _decode_b64(ciphertext_b64)
    except ValueError as exc:
        raise DecryptionError("Schlüsselmaterial beschädigt") from exc

    if len(salt) != _SALT_LEN or len(nonce) != _NONCE_LEN:
        raise DecryptionError("Schlüsselparameter ungültig")

    derived_key = _derive_key(password, pepper, salt=salt)
    aes = AESGCM(derived_key)
    try:
        return aes.decrypt(nonce, ciphertext, None)
    except Exception as exc:  # noqa: BLE001 - AESGCM wirft mehrere Fehler
        raise DecryptionError("Entschlüsselung fehlgeschlagen") from exc


def sign_message(private_key: bytes, message: bytes) -> bytes:
    if isinstance(message, str):
        message = message.encode("utf-8")
    key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
    return key.sign(message)


def sign_message_b64(private_key: bytes, message: bytes) -> str:
    signature = sign_message(private_key, message)
    return _encode_b64(signature)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if isinstance(message, str):
        message = message.encode("utf-8")
    key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    try:
        key.verify(signature, message)
        return True
    except _CryptoInvalidSignature:
        return False


def verify_signature_b64(public_key: bytes, message: bytes, signature_b64: str) -> bool:
    try:
        signature = _decode_b64(signature_b64)
    except ValueError:
        return False
    return verify_signature(public_key, message, signature)


def _derive_key(password: str, pepper: Optional[bytes], *, salt: Optional[bytes] = None) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Passwort fehlt für Key-Derivation")
    pwd_bytes = password.encode("utf-8")
    if pepper:
        pwd_bytes += pepper
    salt = salt or os.urandom(_SALT_LEN)
    return hash_secret_raw(
        secret=pwd_bytes,
        salt=salt,
        time_cost=_ARGON_TIME_COST,
        memory_cost=_ARGON_MEMORY_COST,
        parallelism=_ARGON_PARALLELISM,
        hash_len=_ARGON_HASH_LEN,
        type=Type.ID,
    )


def _encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("Ungültige Base64-Daten") from exc
