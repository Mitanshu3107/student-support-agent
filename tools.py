"""Tools the agent can call, wrapped in the same security pipeline every time:

    model asks for a tool  ->  resolve target  ->  authorize (code)  ->  run  ->  audit record  ->  result

* The signed-in Principal is fixed when the ToolBox is created. No tool takes an identity from the model.
* Tools that read or change a student record accept an optional 'target' (who the question is about).
  Whatever the model passes, code decides: anything other than the signed-in student's own record is
  DENIED and audited. The model's instructions are NOT the safety mechanism - this code is.
* Sensitive changes never execute here. They create a pending approval (approvals.py).
"""
from datetime import datetime, timezone

from approvals import SENSITIVE_FIELDS, ApprovalError, ApprovalStore
from audit import AuditLog
from memory import CATEGORIES, MemoryStore
from retrieval import PolicyRetriever
from security import Principal, authorize, mask_contact, resolve_target
from store import DataPaths, lock, read_json, write_json_atomic

TICKET_CATEGORIES = ("fees", "scholarship", "academic", "technical", "other")

_TARGET = {"type": ["string", "null"], "description": "Whose record the question is about. Leave this field out (do not send null) for the signed-in student's own "
           "record. If the student asks about someone else, pass what they said (a name or student ID) - "
           "the system decides whether that is allowed."}


class ToolError(Exception):
    """Expected, reportable failure (missing record, service down, bad arguments)."""


class PolicyDenied(Exception):
    """A safety rule refused the action (for example the memory guard)."""


TOOL_SCHEMAS = [
    {"name": "get_student_profile",
     "description": "Get a student's programme, batch, term, CGPA and attendance percentage.",
     "input_schema": {"type": "object", "properties": {"target": _TARGET}}},
    {"name": "get_fee_status",
     "description": "Get a student's fee status: total, paid, pending, and each instalment's due date and status.",
     "input_schema": {"type": "object", "properties": {"target": _TARGET}}},
    {"name": "get_scholarship_status",
     "description": "Get a student's scholarship name, status (APPROVED / UNDER_REVIEW / none) and percentage.",
     "input_schema": {"type": "object", "properties": {"target": _TARGET}}},
    {"name": "search_policy",
     "description": "Search the student handbook for policy information (fees rules, late fees, portal failures, scholarships, "
     "course changes, attendance, refunds, support requests). Returns the most relevant sections only. "
     "Use a short query with the key terms of the question.",
     "input_schema": {"type": "object",
                      "properties": {"query": {"type": "string", "description": "Key terms of the policy question"}},
                      "required": ["query"]}},
    {"name": "create_support_request",
     "description": "Create a support ticket for the signed-in student. Use only when the student asks for one or accepts "
     "your offer, and only after you have enough detail for a useful summary.",
     "input_schema": {"type": "object",
                      "properties": {"category": {"type": "string", "enum": list(TICKET_CATEGORIES)},
                                     "summary": {"type": "string", "description": "What the student needs, in 1-3 sentences"}},
                      "required": ["category", "summary"]}},
    {"name": "request_record_change",
     "description": "Ask to change the email address or phone number on a student's record. This is a SENSITIVE action: "
     "it does NOT change anything. It sends the request to staff for approval and returns a pending request ID. "
     "Never tell the student the change was made.",
     "input_schema": {"type": "object",
                      "properties": {"field": {"type": "string", "enum": list(SENSITIVE_FIELDS)},
                                     "new_value": {"type": "string", "description": "The new email address or 10-digit phone number"},
                                     "reason": {"type": "string", "description": "Why the student wants the change (short)"},
                                     "target": _TARGET},
                      "required": ["field", "new_value"]}},
    {"name": "get_my_change_requests",
     "description": "List the signed-in student's own record-change requests and their approval status "
     "(PENDING, EXECUTED, REJECTED).",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "save_memory",
     "description": "Save ONE durable, useful fact about the student for future sessions (programme/specialisation, "
     "preferences, goals, interests). Do NOT save temporary or one-off information, or anything sensitive "
     "(passwords, OTPs, PINs, card/bank/ID numbers, health, finances, contact details). Call only when the student "
     "shares a lasting fact or asks you to remember it.",
     "input_schema": {"type": "object",
                      "properties": {"category": {"type": "string", "enum": list(CATEGORIES)},
                                     "text": {"type": "string", "description": "The fact, in neutral form, under 200 chars"}},
                      "required": ["category", "text"]}},
]

# tool name -> (permission it needs, accepts a 'target' argument)
TOOL_POLICY = {
    "get_student_profile": ("profile:read", True),
    "get_fee_status": ("fees:read", True),
    "get_scholarship_status": ("scholarship:read", True),
    "search_policy": ("policy:search", False),
    "create_support_request": ("ticket:create", False),
    "request_record_change": ("record_change:request", True),
    "get_my_change_requests": ("approvals:read_own", False),
    "save_memory": ("memory:write", False),
}


class ToolBox:
    def __init__(self, principal: Principal, retriever: PolicyRetriever, memory: MemoryStore, paths: DataPaths,
                 audit: AuditLog, approvals: ApprovalStore, session_id: str = ""):
        self.principal = principal
        self.retriever = retriever
        self.memory = memory
        self.paths = paths
        self.audit = audit
        self.approvals = approvals
        self.session_id = session_id
        self._handlers = {
            "get_student_profile": self._profile, "get_fee_status": self._fees,
            "get_scholarship_status": self._scholarship, "search_policy": self._search_policy,
            "create_support_request": self._create_ticket, "request_record_change": self._request_change,
            "get_my_change_requests": self._my_requests, "save_memory": self._save_memory,
        }

    # ---- the one entry point -------------------------------------------------------------------------
    def call(self, name: str, args: dict):
        """Run a tool through resolve -> authorize -> execute -> audit. Never raises.
        Returns (ok, payload, meta) where meta = {decision, audit_id, approval_id, reason}."""
        args = dict(args or {})
        p = self.principal

        def log(decision, reason, result, target=None, approval_id=None, shown_args=None):
            rec = self.audit.record(session_id=self.session_id, actor_id=p.user_id, actor_role=p.role, action=name,
                                    target=target, args=shown_args if shown_args is not None else args,
                                    decision=decision, reason=reason, result=result, approval_id=approval_id)
            return {"decision": decision, "audit_id": rec["audit_id"], "approval_id": approval_id, "reason": reason}

        policy = TOOL_POLICY.get(name)
        if policy is None:
            meta = log("DENIED", "unknown tool", "not executed")
            return False, {"error": f"unknown tool '{name}'"}, meta
        permission, takes_target = policy

        raw_target = args.pop("target", None) if takes_target else None
        target_id, is_own = resolve_target(p, raw_target) if takes_target else (p.student_id, True)
        label = target_id if takes_target and not is_own else (p.student_id if p.student_id else None)
        shown = self._shown_args(name, args)
        if takes_target and raw_target not in (None, ""):
            shown["target"] = str(raw_target)[:80]

        # authorization: a non-own target is always handed to authorize() as a different record
        decision = authorize(p, permission, None if not takes_target else (p.student_id if is_own else "__other__"))
        if not decision.allowed:
            meta = log("DENIED", decision.reason, "not executed", target=label, shown_args=shown)
            return False, {"error": f"Access denied: {decision.reason}. Do not reveal or guess any data; tell the student "
                           "you can only help with their own record.", "denied": True}, meta

        try:
            payload = self._handlers[name](**args)
        except PolicyDenied as e:
            meta = log("DENIED", str(e), "refused by safety rule", target=label, shown_args=shown)
            return False, {"error": f"Refused: {e}", "denied": True}, meta
        except (ToolError, ApprovalError) as e:
            meta = log("ALLOWED", "permission ok", f"error: {e}", target=label, shown_args=shown)
            return False, {"error": str(e)}, meta
        except TypeError as e:  # wrong or missing arguments from the model
            meta = log("ALLOWED", "permission ok", "error: invalid arguments", target=label, shown_args=shown)
            return False, {"error": f"invalid arguments: {e}"}, meta
        except Exception as e:  # unexpected failure: report, don't crash the loop
            meta = log("ALLOWED", "permission ok", f"error: {type(e).__name__}", target=label, shown_args=shown)
            return False, {"error": f"unexpected tool failure: {type(e).__name__}"}, meta

        if isinstance(payload, dict) and payload.get("status") == "PENDING_APPROVAL":
            meta = log("PENDING_APPROVAL", "sensitive action needs staff approval",
                       f"request {payload['approval_id']} created; record unchanged", target=label,
                       approval_id=payload["approval_id"], shown_args=shown)
        else:
            meta = log("ALLOWED", "permission ok", self._result_summary(name, payload), target=label, shown_args=shown)
        return True, payload, meta

    @staticmethod
    def _shown_args(name, args):
        if name == "request_record_change":
            a = dict(args)
            if "new_value" in a and a.get("field") in SENSITIVE_FIELDS:
                a["new_value"] = mask_contact(a["field"], a["new_value"])
            return a
        return dict(args)

    @staticmethod
    def _result_summary(name, payload):
        if name == "create_support_request":
            return f"ticket {payload['ticket_id']} created"
        if name == "save_memory":
            return "memory saved" if payload.get("stored") else f"not saved: {payload.get('reason')}"
        if name == "search_policy":
            return f"{len(payload.get('results', []))} handbook section(s) returned"
        return "returned data to the signed-in student"

    # ---- data tools (always the resolved, authorized record) -------------------------------------------
    def _record(self) -> dict:
        students = read_json(self.paths.students, {})
        sid = self.principal.student_id
        if sid not in students:
            raise ToolError(f"no student record found for ID {sid}")
        return students[sid]

    def _profile(self):
        r = self._record()
        return {k: r[k] for k in ("name", "programme", "batch", "current_term", "cgpa", "attendance_pct")}

    def _fees(self):
        r = self._record()
        if r.get("fee_system_down"):
            raise ToolError("fee system unavailable (HTTP 503) - try again later")
        if not r.get("fees"):
            raise ToolError("no fee data on record for this student")
        return r["fees"]

    def _scholarship(self):
        r = self._record()
        return r.get("scholarship") or {"status": "NONE", "note": "No scholarship application or award on record."}

    # ---- retrieval tool -------------------------------------------------------------------------------
    def _search_policy(self, query: str):
        if not query or not query.strip():
            raise ToolError("query is empty")
        results = self.retriever.search(query, k=2)
        if not results:
            return {"results": [], "note": "No sufficiently relevant handbook section found. Do not guess; tell the student."}
        return {"results": [{"chunk_id": c["chunk_id"], "title": c["title"], "text": c["text"]} for c in results]}

    # ---- action tools ----------------------------------------------------------------------------------
    def _create_ticket(self, category: str, summary: str):
        if category not in TICKET_CATEGORIES:
            raise ToolError(f"category must be one of {list(TICKET_CATEGORIES)}")
        if not summary or len(summary.strip()) < 10:
            raise ToolError("summary too short - ask the student for more detail")
        with lock():
            tickets = read_json(self.paths.tickets, [])
            ticket = {
                "ticket_id": f"SR-{datetime.now().year}-{len(tickets) + 1:04d}",
                "student_id": self.principal.student_id, "category": category,
                "summary": summary.strip()[:500], "status": "OPEN",
                "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            tickets.append(ticket)
            write_json_atomic(self.paths.tickets, tickets)
        return {"ticket_id": ticket["ticket_id"], "status": "OPEN",
                "expected_response": "within 1 working day" if category == "fees" else "within 2 working days"}

    def _request_change(self, field: str, new_value: str, reason: str = ""):
        a = self.approvals.request(self.principal, field, new_value, reason, self.session_id)
        msg = ("A request for this field is already waiting for staff approval." if a.get("already_pending")
               else "Request sent to staff for approval.")
        return {"status": "PENDING_APPROVAL", "approval_id": a["approval_id"], "field": a["field"],
                "message": msg + " Nothing has been changed yet. The student can ask for the status later."}

    def _my_requests(self):
        items = self.approvals.list_for_student(self.principal.student_id)
        return {"requests": [{"approval_id": a["approval_id"], "field": a["field"],
                              "new_value": mask_contact(a["field"], a["new_value"]), "status": a["status"],
                              "staff_note": a["decision_note"]} for a in items]}

    # ---- memory tool ----------------------------------------------------------------------------------
    def _save_memory(self, category: str, text: str):
        res = self.memory.add(self.principal.student_id, category, text, self.session_id)
        if not res["stored"] and res.get("reason") != "already remembered":
            if res["reason"].startswith("category"):
                raise ToolError(res["reason"])
            raise PolicyDenied(res["reason"])
        return res
