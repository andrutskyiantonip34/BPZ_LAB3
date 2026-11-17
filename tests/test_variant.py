import base64
import hmac
import os
import sys

os.environ.setdefault("AUTH_PEPPER", "lab3-test-pepper")  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pyotp

from auth import passwords
from auth.anderson import entropy_bits, min_length, required_space
from auth.lockout import ProgressiveLockout
from auth.passwords import hash_password, hash_password_insecure, verify_password
from auth.totp import hotp, totp, verify_totp

SECRET = b"12345678901234567890"  # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом


def test_anderson_control_example():
    # The control example from the lecture gives G = 1.296e12 and L = 7 for A = 95.
    g = required_space(10, 90, 1e-6)
    assert round(g) == 1_296_000_000_000
    assert min_length(g, 95) == 7
    assert round(entropy_bits(95, 7), 1) == 46.0


def test_anderson_variant_space():
    # Variant 1 (R=12/min, T=120 days, P=1e-6) needs a space of 2.0736e12 passwords.
    assert round(required_space(12, 120, 1e-6)) == 2_073_600_000_000


def test_anderson_variant_lengths():
    # Minimal length for variant 1 is 9, 7 and 7 for alphabets of 26, 62 and 95 symbols.
    g = required_space(12, 120, 1e-6)
    assert {a: min_length(g, a) for a in (26, 62, 95)} == {26: 9, 62: 7, 95: 7}


def test_hash_verify_roundtrip():
    # A password verifies against its own stored hash.
    assert verify_password(hash_password("correct horse"), "correct horse")


def test_wrong_password_rejected():
    # A different password is rejected.
    assert not verify_password(hash_password("correct horse"), "wrong")


def test_salt_is_unique():
    # The same password hashed twice gives different results because of a fresh salt.
    assert hash_password("same") != hash_password("same")


def test_stored_format_contains_algorithm_cost_and_salt():
    # The stored string is bcrypt$12$<bcrypt hash> with a 22-char (16-byte) salt inside.
    stored = hash_password("format")
    algo, cost, dk = stored.split("$", 2)
    assert (algo, cost) == ("bcrypt", "12")
    assert dk.startswith("$2b$12$") and len(dk) == 60


def test_insecure_hash_repeats_for_same_password():
    # The vulnerable SHA-256 storage returns the same value for the same password.
    assert hash_password_insecure("password123") == hash_password_insecure("password123")


def test_pepper_is_required_for_verification(monkeypatch):
    # A hash made with one pepper does not verify when the server pepper is different.
    stored = hash_password("peppered")
    monkeypatch.setattr(passwords, "PEPPER", b"other-pepper")
    assert not verify_password(stored, "peppered")


def test_malformed_stored_value_rejected():
    # Broken or foreign stored strings are rejected instead of raising an error.
    for bad in ("", "bcrypt", "sha256$1$abc", "bcrypt$12$not-a-bcrypt-hash"):
        assert not verify_password(bad, "x")


def test_long_password_is_not_truncated():
    # Passwords longer than the 72-byte bcrypt limit are fully taken into account.
    long_pw = "a" * 100
    stored = hash_password(long_pw)
    assert verify_password(stored, long_pw)
    assert not verify_password(stored, "a" * 72)


def test_verify_uses_constant_time_compare(monkeypatch):
    # verify_password compares hashes with hmac.compare_digest.
    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(passwords.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    verify_password(hash_password("ct"), "ct")
    assert calls


def test_first_failures_do_not_lock():
    # The first two failed attempts do not block the account.
    lock = ProgressiveLockout()
    lock.record_attempt("alice", False, 0)
    lock.record_attempt("alice", False, 1)
    assert lock.is_allowed("alice", 1)


def test_lock_after_limit_and_boundary():
    # The third failure blocks for 30 s; at 29.9 s it is blocked, exactly at 30 s it is allowed.
    lock = ProgressiveLockout()
    for t in (0, 1, 2):
        lock.record_attempt("alice", False, t)
    assert not lock.is_allowed("alice", 2 + 29.9)
    assert lock.is_allowed("alice", 2 + 30)


def test_delay_doubles():
    # Each further failure doubles the delay: 30, 60, 120, 240 seconds.
    lock = ProgressiveLockout()
    assert [lock.delay_for(n) for n in range(1, 7)] == [0, 0, 30, 60, 120, 240]


def test_delay_is_capped():
    # The delay never exceeds max_delay of one hour.
    lock = ProgressiveLockout()
    assert lock.delay_for(20) == 3600
    assert lock.delay_for(5000) == 3600


def test_success_resets_counter():
    # A successful login clears the failure counter and the lock.
    lock = ProgressiveLockout()
    for t in (0, 1, 2):
        lock.record_attempt("alice", False, t)
    lock.record_attempt("alice", True, 40)
    lock.record_attempt("alice", False, 41)
    assert lock.is_allowed("alice", 41)


def test_accounts_are_independent():
    # Locking one account does not affect another account.
    lock = ProgressiveLockout()
    for t in (0, 1, 2):
        lock.record_attempt("alice", False, t)
    assert not lock.is_allowed("alice", 3)
    assert lock.is_allowed("bob", 3)


def test_totp_control_vector():
    # TOTP for the RFC 6238 secret at T = 59 s equals 287082.
    assert totp(SECRET, at=59) == "287082"


def test_hotp_control_vectors():
    # HOTP matches all ten RFC 4226 test values for counters 0..9.
    expected = ["755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489"]
    assert [hotp(SECRET, c) for c in range(10)] == expected


def test_totp_rfc6238_eight_digit_vectors():
    # 8-digit SHA-1 TOTP values match the RFC 6238 appendix B table.
    table = {59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
             1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130"}
    assert {t: totp(SECRET, at=t, digits=8) for t in table} == table


def test_totp_matches_pyotp():
    # Our TOTP gives the same codes as the pyotp reference library.
    ref = pyotp.TOTP(base64.b32encode(SECRET).decode())
    for t in (0, 59, 1_700_000_000, 1_763_100_000):
        assert totp(SECRET, at=t) == ref.at(t)


def test_verify_totp_accepts_adjacent_step():
    # A code from the previous 30 s step is still accepted, two steps back is rejected.
    code = totp(SECRET, at=1000)
    assert verify_totp(SECRET, code, at=1000 + 30)
    assert not verify_totp(SECRET, code, at=1000 + 90)


def test_verify_totp_rejects_wrong_code():
    # A wrong six-digit code is rejected.
    assert not verify_totp(SECRET, "000000", at=59)


def test_verify_totp_uses_constant_time_compare(monkeypatch):
    # verify_totp compares codes with hmac.compare_digest.
    import auth.totp as mod
    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(mod.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    verify_totp(SECRET, "287082", at=59)
    assert calls
