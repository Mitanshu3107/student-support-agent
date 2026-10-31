"""Append-only audit log with a hash chain.

Every record says WHO (actor), WHAT was attempted (action, target, arguments with secrets removed),
whether it was ALLOWED / DENIED / PENDING_APPROVAL / APPROVED / REJECTED, why, and the final RESULT.
Each record also stores the hash of the previous record, so editing or deleting an old line breaks the
chain and verify() reports where. (This detects tampering; it does not prevent someone with file access
from rewriting the whole file - in production the log would go to write-once storage.)
"""
import hashlib
import json
import os
from datetime import datetime, timezone

from security import redact_obj
from store import lock

DECISIONS = ("ALLOWED", "DENIED", "PENDING_APPROVAL", "APPROVED", "REJECTED")
GENESIS = "0" * 64


def _digest(prev_hash: str, record: dict) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str):
        self.path = path

    def _last(self):
        """(count, last_hash) of the existing log. Cached by file size, so appending stays cheap; if any other
        writer or an edit changed the file size, the log is re-read."""
        size = os.path.getsize(self.path) if os.path.exists(self.path) else 0
        cached = getattr(self, "_cache", None)
        if cached and cached[0] == size:
            return cached[1], cached[2]
        count, last = 0, GENESIS
        if size:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        count += 1
                        last = json.loads(line)["hash"]
        self._cache = (size, count, last)
        return count, last

    def record(self, *, session_id="", actor_id, actor_role, action, target=None, args=None,
               decision, reason="", result="", approval_id=None) -> dict:
        assert decision in DECISIONS, decision
        with lock():
            count, prev = self._last()
            rec = {
                "audit_id": f"A-{count + 1:06d}",
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "session_id": session_id,
                "actor": {"user_id": actor_id, "role": actor_role},
                "action": action,
                "target": target,
                "args": redact_obj(args or {}),
                "decision": decision,
                "reason": reason,
                "approval_id": approval_id,
                "result": result,
                "prev_hash": prev,
            }
            rec["hash"] = _digest(prev, {k: v for k, v in rec.items() if k != "hash"})
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self._cache = (os.path.getsize(self.path), count + 1, rec["hash"])
            return rec

    def read(self) -> list:
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def verify(self):
        """Return (ok, number_of_records, first_bad_audit_id_or_None)."""
        prev, n = GENESIS, 0
        for rec in self.read():
            n += 1
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("prev_hash") != prev or _digest(prev, body) != rec.get("hash"):
                return False, n, rec.get("audit_id")
            prev = rec["hash"]
        return True, n, None
