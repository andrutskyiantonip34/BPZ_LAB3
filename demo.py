import os
import sys
import time

os.environ.setdefault("AUTH_PEPPER", "lab3-demo-pepper")  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом

from auth.anderson import entropy_bits, min_length, required_space
from auth.lockout import ProgressiveLockout
from auth.passwords import hash_password, hash_password_insecure, verify_password
from auth.totp import hotp, totp, verify_totp

SECRET = b"12345678901234567890"  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом


def step2() -> None:
    g = required_space(12, 120, 1e-6)
    print(f"G >= {g:.4e}")
    for a in (26, 62, 95):
        n = min_length(g, a)
        print(f"A={a} L={n} H={entropy_bits(a, n):.1f} bit")


def step3() -> None:
    h = hash_password("correct horse")
    print(h)
    print(verify_password(h, "correct horse"))
    print(verify_password(h, "wrong"))
    print(hash_password("same") != hash_password("same"))


def step4() -> None:
    a = hash_password_insecure("password123")
    b = hash_password_insecure("password123")
    print(a)
    print(a == b)
    print(hash_password("password123") != hash_password("password123"))
    n = 20
    t0 = time.perf_counter()
    for _ in range(n):
        hash_password_insecure("password123")
    sha = (time.perf_counter() - t0) / n
    t0 = time.perf_counter()
    for _ in range(n):
        hash_password("password123")
    kdf = (time.perf_counter() - t0) / n
    print(f"sha256: {sha * 1e6:.1f} us, bcrypt(12): {kdf * 1e3:.1f} ms, ratio: {kdf / sha:.0f}x")


def step5() -> None:
    lock = ProgressiveLockout()
    now = 0.0
    for i in range(1, 6):
        lock.record_attempt("alice", False, now)
        print(f"fail {i} at t={now:.0f}: allowed={lock.is_allowed('alice', now)}, "
              f"wait={lock.remaining('alice', now):.0f}s")
        now += lock.remaining("alice", now)
    print("allowed at t+0:", lock.is_allowed("alice", now))
    lock.record_attempt("alice", True, now)
    print("after success:", lock.is_allowed("alice", now))


def step6() -> None:
    print("TOTP(T=59):", totp(SECRET, at=59))
    print("HOTP(0):", hotp(SECRET, 0), "HOTP(1):", hotp(SECRET, 1))
    print("verify 287082 at 59:", verify_totp(SECRET, "287082", at=59))
    print("verify 000000 at 59:", verify_totp(SECRET, "000000", at=59))


STEPS = {"2": step2, "3": step3, "4": step4, "5": step5, "6": step6}

if __name__ == "__main__":
    for k in sys.argv[1:] or STEPS:
        STEPS[k]()
