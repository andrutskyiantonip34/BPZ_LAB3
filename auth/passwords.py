from __future__ import annotations

import base64
import hashlib
import hmac
import os

import bcrypt


PEPPER = os.environ.get("AUTH_PEPPER", "").encode()
BCRYPT_COST = 12


# ВРАЗЛИВИЙ зразок (для порівняння у звіті) — НЕ використовувати:
def hash_password_insecure(password: str) -> str:
    # ВРАЗЛИВО: швидка хеш-функція без солі — вразлива до райдужних таблиць.
    return hashlib.sha256(password.encode()).hexdigest()


def _prepare(password: str) -> bytes:
    data = _peppered(password.encode())
    return base64.b64encode(hashlib.sha256(data).digest())


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_COST)
    dk = bcrypt.hashpw(_prepare(password), salt).decode()
    return f"bcrypt${BCRYPT_COST}${dk}"


def verify_password(stored: str, password: str) -> bool:
    try:
        algo, cost, expected = stored.split("$", 2)
    except ValueError:
        return False
    if algo != "bcrypt" or not cost.isdigit():
        return False
    try:
        dk = bcrypt.hashpw(_prepare(password), expected.encode()).decode()
    except ValueError:
        return False
    return hmac.compare_digest(dk.encode(), expected.encode())


def _peppered(data: bytes) -> bytes:
    return hmac.new(PEPPER, data, hashlib.sha256).digest() if PEPPER else data
