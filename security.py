"""Identity, permissions and redaction. Everything here is ordinary code: the language model cannot
change a permission, and a prompt cannot talk this module into allowing something.

Model of access
  * A Principal is created ONLY by auth.authenticate() after a correct sign-in (or by tests).
  * Each tool/action maps to one permission. A role holds a fixed set of permissions (ROLE_PERMISSIONS).
  * Student-scoped permissions additionally require the target record to be the principal's own.
"""
import re
from dataclasses import dataclass

# permission -> True when it only applies to the principal's OWN student record
PERMISSIONS = {
    "profile:read": True,
    "fees:read": True,
    "scholarship:read": True,
    "policy:search": False,
    "ticket:create": True,
    "memory:write": True,
    "record_change:request": True,
    "approvals:read_own": True,
    "approvals:read_all": False,
    "approvals:decide": False,
    "audit:read": False,
}

ROLE_PERMISSIONS = {
    "student": {"profile:read", "fees:read", "scholarship:read", "policy:search", "ticket:create",
                "memory:write", "record_change:request", "approvals:read_own"},
    "staff": {"approvals:read_all", "approvals:decide", "audit:read"},
}


@dataclass(frozen=True)
class Principal:
    user_id: str                 # what they signed in as, e.g. S1001 or STAFF01
    role: str                    # "student" | "staff"
    student_id: str = None       # set for students: the ONLY student record they may touch
    display_name: str = ""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str = ""


def authorize(principal: Principal, permission: str, target_student_id: str = None) -> Decision:
    """Central permission check. target_student_id is the record the action is about (None = no record)."""
    if principal is None:
        return Decision(False, "not signed in")
    if permission not in PERMISSIONS:
        return Decision(False, f"unknown permission '{permission}'")
    if permission not in ROLE_PERMISSIONS.get(principal.role, set()):
        return Decision(False, f"role '{principal.role}' is not allowed to perform '{permission}'")
    if PERMISSIONS[permission] and target_student_id is not None and target_student_id != principal.student_id:
        return Decision(False, "students may only access their own record")
    return Decision(True, "allowed")


def resolve_target(principal: Principal, target) -> tuple:
    """Turn the 'target' text a tool received into a student ID for authorization.

    Returns (student_id_or_None, is_own). Anything that is not clearly the signed-in student
    (their own ID or own name, or 'me'/'my'/empty) is treated as ANOTHER student and is never looked up,
    so the system cannot be used to find out whether some other student exists."""
    if target is None:
        return principal.student_id, True
    t = " ".join(str(target).split()).strip().lower()
    own = {"", "me", "my", "myself", "self", "own", "mine", (principal.student_id or "").lower(),
           (principal.display_name or "").lower()}
    if t in own:
        return principal.student_id, True
    return str(target)[:80], False


# ---- redaction: keep secrets out of logs, traces and replayed history -------------------------------
_REDACTIONS = [
    (re.compile(r"(?i)\b(otp|one[- ]time (?:password|code)|password|passcode|passwd|pin|cvv|cvc|secret|token)\b"
                r"(\s*(?:is|was|=|:|-)\s*|\s+)([^\s,;]+)"), r"\1\2[REDACTED]"),
    # a short code appearing soon after a secret keyword: "the OTP I received is 482913", "my pin code is 1234"
    (re.compile(r"(?i)\b(otp|pin|cvv|cvc|passcode|verification code|one[- ]time (?:password|code))\b([^.\n]{0,40}?)\b(\d{4,8})\b"),
     r"\1\2[REDACTED]"),
    # long digit runs (card numbers). 13+ digits so a phone number written as "+91 98765 01234" (12 digits) is kept.
    (re.compile(r"(?:\d[ -]?){13,19}"), "[REDACTED-NUMBER]"),
]


def redact(text):
    """Mask credentials and long numbers in free text. Returns text unchanged if there is nothing to mask."""
    if not isinstance(text, str):
        return text
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def redact_obj(obj):
    """redact() applied to every string inside dicts/lists."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj


def mask_contact(field: str, value: str) -> str:
    """Show enough to recognise a contact value in logs without storing it in full."""
    value = str(value)
    if field == "email" and "@" in value:
        name, _, domain = value.partition("@")
        return f"{name[:1]}***@{domain}"
    digits = re.sub(r"\D", "", value)
    return f"******{digits[-3:]}" if len(digits) >= 3 else "***"
