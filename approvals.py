"""Human approval for sensitive actions.

Sensitive action implemented: changing the contact details (email / phone) on a student's own record.
Why this one: contact details are used for account recovery and notices, so a wrong change can lock a
student out or send their private information to someone else.

Flow
  1. The signed-in student asks (through the agent) -> request() stores a PENDING approval. NOTHING is changed.
  2. A staff member (role 'staff', a different person from the student) opens the approval console and calls decide().
  3. approve -> the change is applied by code (apply step below) and the approval becomes EXECUTED.
     reject  -> the approval becomes REJECTED and the record is never touched.
  A request can be decided exactly once. The language model has no tool that can approve anything.
"""
import re
from datetime import datetime, timezone

from audit import AuditLog
from security import Principal, authorize, mask_contact
from store import DataPaths, lock, read_json, write_json_atomic

SENSITIVE_FIELDS = ("email", "phone")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


class ApprovalError(Exception):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalise_value(field: str, value: str) -> str:
    value = (value or "").strip()
    if field == "email":
        if not _EMAIL.match(value) or len(value) > 120:
            raise ApprovalError("that does not look like a valid email address")
        return value.lower()
    digits = re.sub(r"[\s\-()]", "", value)
    digits = re.sub(r"^\+?91", "", digits) if len(re.sub(r"\D", "", digits)) == 12 else digits
    if not re.fullmatch(r"\d{10}", digits):
        raise ApprovalError("phone number must be 10 digits")
    return digits


class ApprovalStore:
    def __init__(self, paths: DataPaths, audit: AuditLog):
        self.paths = paths
        self.audit = audit

    # ---- reading ----------------------------------------------------------------------------------
    def _all(self) -> list:
        return read_json(self.paths.approvals, [])

    def get(self, approval_id: str):
        return next((a for a in self._all() if a["approval_id"] == approval_id), None)

    def list_for_student(self, student_id: str) -> list:
        return [a for a in self._all() if a["student_id"] == student_id]

    def list_all(self, status: str = None) -> list:
        return [a for a in self._all() if status is None or a["status"] == status]

    # ---- step 1: a student asks ------------------------------------------------------------------------
    def request(self, principal: Principal, field: str, new_value: str, reason: str, session_id: str = "") -> dict:
        """Create a PENDING approval for the principal's OWN record. Never changes the record."""
        if field not in SENSITIVE_FIELDS:
            raise ApprovalError(f"only these fields can be changed through a request: {list(SENSITIVE_FIELDS)}")
        new_value = normalise_value(field, new_value)
        with lock():
            students = read_json(self.paths.students, {})
            record = students.get(principal.student_id)
            if record is None:
                raise ApprovalError("no student record found for your account")
            if str(record.get(field, "")).lower() == new_value:
                raise ApprovalError(f"your {field} on record is already that value")
            approvals = self._all()
            for a in approvals:
                if a["student_id"] == principal.student_id and a["field"] == field and a["status"] == "PENDING":
                    return {**a, "already_pending": True}
            approval = {
                "approval_id": f"AP-{len(approvals) + 1:04d}",
                "student_id": principal.student_id,
                "requested_by": principal.user_id,
                "field": field,
                "new_value": new_value,
                "reason": (reason or "")[:200],
                "status": "PENDING",
                "created_at": _now(),
                "decided_by": None, "decided_at": None, "decision_note": None, "result": None,
            }
            approvals.append(approval)
            write_json_atomic(self.paths.approvals, approvals)
            return approval

    # ---- step 2/3: staff decide --------------------------------------------------------------------------
    def decide(self, principal: Principal, approval_id: str, approve: bool, note: str = "", session_id: str = "") -> dict:
        """Approve (and execute) or reject. Only a principal holding 'approvals:decide' may call this."""
        verdict = authorize(principal, "approvals:decide")
        if not verdict.allowed:
            self.audit.record(session_id=session_id, actor_id=principal.user_id, actor_role=principal.role,
                              action="approval.decide", target=approval_id, args={"approve": approve},
                              decision="DENIED", reason=verdict.reason, result="not executed", approval_id=approval_id)
            raise ApprovalError(f"permission denied: {verdict.reason}")
        with lock():
            approvals = self._all()
            a = next((x for x in approvals if x["approval_id"] == approval_id), None)
            if a is None:
                raise ApprovalError("no such approval request")
            if a["status"] != "PENDING":
                self.audit.record(session_id=session_id, actor_id=principal.user_id, actor_role=principal.role,
                                  action="approval.decide", target=approval_id, args={"approve": approve},
                                  decision="DENIED", reason=f"already {a['status']}", result="not executed",
                                  approval_id=approval_id)
                raise ApprovalError(f"this request was already {a['status'].lower()}")
            a["decided_by"], a["decided_at"], a["decision_note"] = principal.user_id, _now(), (note or "")[:200]
            masked = mask_contact(a["field"], a["new_value"])
            ctx = {"student_id": a["student_id"], "field": a["field"], "new_value": masked}
            if not approve:
                a["status"], a["result"] = "REJECTED", "not executed"
                write_json_atomic(self.paths.approvals, approvals)
                self.audit.record(session_id=session_id, actor_id=principal.user_id, actor_role=principal.role,
                                  action="approval.decide", target=a["student_id"], args=ctx, decision="REJECTED",
                                  reason=a["decision_note"] or "rejected by staff",
                                  result="action NOT executed; record unchanged", approval_id=approval_id)
                return a
            self.audit.record(session_id=session_id, actor_id=principal.user_id, actor_role=principal.role,
                              action="approval.decide", target=a["student_id"], args=ctx, decision="APPROVED",
                              reason=a["decision_note"] or "approved by staff", result="executing", approval_id=approval_id)
            try:  # the actual change - happens only here, only after approval
                students = read_json(self.paths.students, {})
                students[a["student_id"]][a["field"]] = a["new_value"]
                write_json_atomic(self.paths.students, students)
                a["status"], a["result"] = "EXECUTED", f"{a['field']} updated"
            except Exception as e:  # leave a clear trail if execution fails
                a["status"], a["result"] = "FAILED", f"execution failed: {type(e).__name__}"
            write_json_atomic(self.paths.approvals, approvals)
            self.audit.record(session_id=session_id, actor_id=principal.user_id, actor_role=principal.role,
                              action="record_change.execute", target=a["student_id"], args=ctx,
                              decision="ALLOWED", reason=f"approved ({approval_id})", result=a["result"],
                              approval_id=approval_id)
            return a
