import base64

import pytest

from crypto_utils import (
    DecryptionError,
    generate_user_keypair,
    encrypt_private_key,
    decrypt_private_key,
    sign_message,
    sign_message_b64,
    verify_signature,
    verify_signature_b64,
)


def test_generate_user_keypair_creates_distinct_keys():
    pair = generate_user_keypair()
    assert len(pair.private_key) == 32
    assert len(pair.public_key) == 32
    assert base64.b64decode(pair.private_key_b64()) == pair.private_key
    assert base64.b64decode(pair.public_key_b64()) == pair.public_key


def test_encrypt_private_key_roundtrip():
    pair = generate_user_keypair()
    payload = encrypt_private_key("TopSecret!", pair.private_key)
    restored = decrypt_private_key("TopSecret!", payload)
    assert restored == pair.private_key


def test_encrypt_private_key_with_pepper():
    pair = generate_user_keypair()
    pepper = b"pepper"
    payload = encrypt_private_key("TopSecret!", pair.private_key, pepper=pepper)
    restored = decrypt_private_key("TopSecret!", payload, pepper=pepper)
    assert restored == pair.private_key


def test_decrypt_private_key_rejects_wrong_password():
    pair = generate_user_keypair()
    payload = encrypt_private_key("TopSecret!", pair.private_key)
    with pytest.raises(DecryptionError):
        decrypt_private_key("WrongPassword", payload)


def test_sign_and_verify_message():
    pair = generate_user_keypair()
    message = b"hello-world"
    signature = sign_message(pair.private_key, message)
    assert verify_signature(pair.public_key, message, signature)
    assert not verify_signature(pair.public_key, b"tampered", signature)


def test_sign_and_verify_message_base64_helpers():
    pair = generate_user_keypair()
    message = "payload-string"
    signature_b64 = sign_message_b64(pair.private_key, message)
    assert isinstance(signature_b64, str)
    assert verify_signature_b64(pair.public_key, message, signature_b64)
    assert not verify_signature_b64(pair.public_key, message, signature_b64 + "a")
