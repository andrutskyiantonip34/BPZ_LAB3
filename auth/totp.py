from __future__ import annotations

import hashlib
import hmac
import struct
import time


def hotp(secret: bytes, counter: int, digits: int = 6, digest=hashlib.sha1) -> str:
    mac = hmac.new(secret, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


def totp(secret: bytes, at: float | None = None, step: int = 30, digits: int = 6,
         digest=hashlib.sha1) -> str:
    now = time.time() if at is None else at
    return hotp(secret, int(now // step), digits, digest)


def verify_totp(secret: bytes, code: str, at: float | None = None, step: int = 30,
                window: int = 1, digits: int = 6) -> bool:
    now = time.time() if at is None else at
    counter = int(now // step)
    ok = False
    for delta in range(-window, window + 1):
        candidate = hotp(secret, counter + delta, digits)
        ok |= hmac.compare_digest(candidate.encode(), code.encode())
    return ok
