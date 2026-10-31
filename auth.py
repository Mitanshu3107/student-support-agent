"""Sign-in. Passwords are stored only as salted PBKDF2 hashes in data/users.json.

The demo accounts and passwords are listed in the README; they are for this assignment only.
A Principal (the verified identity) is created here and nowhere else in the application.
"""
import hashlib
import hmac
import time

from audit import AuditLog
from security import Principal
from store import DataPaths, read_json

ITERATIONS = 200_000
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300
_failures = {}  # user_id -> (count, locked_until)  (in memory: resets when the app restarts)


class AuthError(Exception):
    pass


def hash_password(password: str, salt_hex: str, iterations: int = ITERATIONS) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations).hex()


def authenticate(paths: DataPaths, user_id: str, password: str, session_id: str = "") -> Principal:
    """Return a Principal or raise AuthError. The error text is identical for 'no such user' and
    'wrong password' so it cannot be used to discover which IDs exist."""
    audit = AuditLog(paths.audit)
    uid = (user_id or "").strip().upper()[:40]
    count, locked_until = _failures.get(uid, (0, 0.0))
    if locked_until > time.time():
        audit.record(session_id=session_id, actor_id=uid or "?", actor_role="unknown", action="login",
                     decision="DENIED", reason="account temporarily locked after repeated failures", result="no session")
        raise AuthError("Too many failed attempts. Try again in a few minutes.")
    user = read_json(paths.users, {}).get(uid)
    # always do the hash work so timing does not reveal whether the user exists
    salt = user["salt"] if user else "00" * 16
    candidate = hash_password(password or "", salt, user["iterations"] if user else ITERATIONS)
    ok = bool(user) and hmac.compare_digest(candidate, user["hash"])
    if not ok:
        count += 1
        _failures[uid] = (count, time.time() + LOCKOUT_SECONDS if count >= MAX_FAILURES else 0.0)
        audit.record(session_id=session_id, actor_id=uid or "?", actor_role="unknown", action="login",
                     decision="DENIED", reason="invalid ID or password", result="no session")
        raise AuthError("Invalid ID or password.")
    _failures.pop(uid, None)
    principal = Principal(user_id=uid, role=user["role"], student_id=user.get("student_id"),
                          display_name=user.get("display_name", uid))
    audit.record(session_id=session_id, actor_id=uid, actor_role=principal.role, action="login",
                 decision="ALLOWED", reason="credentials verified", result="session started")
    return principal
