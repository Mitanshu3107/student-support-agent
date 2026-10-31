"""Deterministic security tests. NO language model and NO API key are involved.

Why these exist: the assignment requires authorization to be enforced in ordinary code, not by an LLM
instruction. So these tests call the tools and the approval service directly, exactly as a compromised or
tricked model would, and check that the code refuses. Each test runs in its own throw-away copy of data/
(a fresh students.json, audit log, approvals file), so the real data is never touched.

Used by:  evaluate.py (final report)   and   tests/test_units.py (quick check).
"""
import json
import os
import shutil
import tempfile

import auth
from agent import build_agent
from approvals import ApprovalError, ApprovalStore
from audit import AuditLog
from auth import AuthError, authenticate
from llm import LLMResponse
from memory import MemoryStore
from retrieval import PolicyRetriever
from security import Principal, authorize, redact
from store import DataPaths, read_json
from tools import ToolBox

SRC = DataPaths()
STAFF_LOGIN = ("STAFF01", "staff-demo")


def make_workdir() -> DataPaths:
    """A private copy of the data folder with the original (seed) student records."""
    d = tempfile.mkdtemp(prefix="ssa_sec_")
    for name in ("handbook.md", "users.json"):
        shutil.copyfile(os.path.join(SRC.dir, name), os.path.join(d, name))
    seed = os.path.join(SRC.dir, "students.seed.json")
    shutil.copyfile(seed if os.path.exists(seed) else SRC.students, os.path.join(d, "students.json"))
    return DataPaths(d)


class Env:
    """One isolated deployment: data files, audit log, approvals, retriever, memory."""

    def __init__(self):
        self.paths = make_workdir()
        self.audit = AuditLog(self.paths.audit)
        self.approvals = ApprovalStore(self.paths, self.audit)
        self.retriever = PolicyRetriever(self.paths.handbook)
        self.memory = MemoryStore(self.paths.memory)

    def student(self, sid: str) -> Principal:  # demo password convention: S1001 -> demo1001
        return authenticate(self.paths, sid, "demo" + sid[1:])

    def staff(self) -> Principal:
        return authenticate(self.paths, *STAFF_LOGIN)

    def toolbox(self, principal: Principal, session: str = "suite") -> ToolBox:
        return ToolBox(principal, self.retriever, self.memory, self.paths, self.audit, self.approvals, session)

    def record(self, sid: str) -> dict:
        return read_json(self.paths.students, {})[sid]

    def all_text(self) -> str:
        """Everything written to disk by this deployment (for 'the secret appears nowhere' checks)."""
        out = []
        for name in os.listdir(self.paths.dir):
            if name.endswith((".json", ".jsonl")) and name not in ("users.json",):
                with open(os.path.join(self.paths.dir, name), encoding="utf-8") as f:
                    out.append(f.read())
        return "\n".join(out)


# ---- registry -----------------------------------------------------------------------------------------
TESTS = []


def scenario(tid, name, group, expected):
    def deco(fn):
        TESTS.append({"id": tid, "name": name, "group": group, "expected": expected, "fn": fn})
        return fn
    return deco


def _leaks(payload, markers=("Diya", "Merit", "3.71", "450000", "FULLY_PAID", "diya.shah")):
    text = json.dumps(payload)
    return [m for m in markers if m in text]


# ---- privacy: another student's record ----------------------------------------------------------------
@scenario("D01", "Own fee / scholarship / profile (allowed)", "privacy", "ALLOWED")
def own_allowed(env, stats):
    tb = env.toolbox(env.student("S1001"))
    r1 = tb.call("get_fee_status", {})
    r2 = tb.call("get_scholarship_status", {"target": "me"})
    r3 = tb.call("get_student_profile", {"target": "S1001"})
    ok = (r1[0] and r1[1].get("total_paid") == 300000 and r1[2]["decision"] == "ALLOWED"
          and r2[0] and r2[2]["decision"] == "ALLOWED" and r3[0] and r3[2]["decision"] == "ALLOWED")
    return ok, f"decisions: {r1[2]['decision']}, {r2[2]['decision']}, {r3[2]['decision']}; fee data returned"


TARGETS = ["S1002", "s1002 ", "Diya Shah", "S1003", "everyone", "S1002; S1001", "../S1002"]


def _blocked_reads(tool):
    def run(env, stats):
        tb = env.toolbox(env.student("S1001"))
        bad = []
        for t in TARGETS:
            ok, payload, meta = tb.call(tool, {"target": t})
            stats["privacy_attempts"] = stats.get("privacy_attempts", 0) + 1
            if (not ok) and meta["decision"] == "DENIED" and payload.get("denied") and not _leaks(payload):
                stats["privacy_blocked"] = stats.get("privacy_blocked", 0) + 1
            else:
                bad.append(t)
        return not bad, (f"{len(TARGETS)} attempts, all DENIED, no data returned" if not bad else f"NOT blocked: {bad}")
    return run


scenario("D02", "Read another student's PROFILE (blocked)", "privacy", "DENIED")(_blocked_reads("get_student_profile"))
scenario("D03", "Read another student's FEES (blocked)", "privacy", "DENIED")(_blocked_reads("get_fee_status"))
scenario("D04", "Read another student's SCHOLARSHIP (blocked)", "privacy", "DENIED")(_blocked_reads("get_scholarship_status"))


@scenario("D05", "Change another student's email (blocked)", "privacy", "DENIED")
def modify_other(env, stats):
    before = env.record("S1002")["email"]
    tb = env.toolbox(env.student("S1001"))
    ok, payload, meta = tb.call("request_record_change",
                                {"field": "email", "new_value": "hacker@example.com", "target": "S1002"})
    stats["privacy_attempts"] = stats.get("privacy_attempts", 0) + 1
    blocked = (not ok) and meta["decision"] == "DENIED" and not env.approvals.list_all() and env.record("S1002")["email"] == before
    stats["privacy_blocked"] = stats.get("privacy_blocked", 0) + int(blocked)
    return blocked, f"decision {meta['decision']}; no approval created; S1002 email unchanged"


# ---- sensitive action: approval -----------------------------------------------------------------------
@scenario("D06", "Sensitive change of OWN phone waits for approval", "approval", "PENDING_APPROVAL")
def pending(env, stats):
    before = env.record("S1001")["phone"]
    tb = env.toolbox(env.student("S1001"))
    ok, payload, meta = tb.call("request_record_change", {"field": "phone", "new_value": "9876501234", "reason": "lost SIM"})
    unchanged = env.record("S1001")["phone"] == before
    stats["sensitive_requests"] = stats.get("sensitive_requests", 0) + 1
    stats["executed_before_approval"] = stats.get("executed_before_approval", 0) + int(not unchanged)
    pend = env.approvals.list_all("PENDING")
    good = ok and meta["decision"] == "PENDING_APPROVAL" and payload["status"] == "PENDING_APPROVAL" and unchanged and len(pend) == 1
    return good, f"decision {meta['decision']}, approval {payload.get('approval_id')} PENDING, phone still {before}"


@scenario("D07", "Staff APPROVES -> change executes (audited)", "approval", "APPROVED + executed")
def approve(env, stats):
    tb = env.toolbox(env.student("S1001"))
    _, payload, _ = tb.call("request_record_change", {"field": "phone", "new_value": "9876501234"})
    unchanged_before = env.record("S1001")["phone"] == "9876500001"
    stats["sensitive_requests"] = stats.get("sensitive_requests", 0) + 1
    stats["executed_before_approval"] = stats.get("executed_before_approval", 0) + int(not unchanged_before)
    res = env.approvals.decide(env.staff(), payload["approval_id"], True, "verified by phone")
    recs = env.audit.read()
    decide = [r for r in recs if r["action"] == "approval.decide" and r["decision"] == "APPROVED"]
    execute = [r for r in recs if r["action"] == "record_change.execute"]
    good = (res["status"] == "EXECUTED" and env.record("S1001")["phone"] == "9876501234" and decide
            and decide[0]["actor"]["user_id"] == "STAFF01" and decide[0]["target"] == "S1001" and execute
            and execute[0]["approval_id"] == payload["approval_id"] and res["requested_by"] == "S1001")
    return bool(good), "requester S1001, approver STAFF01, APPROVED then EXECUTED, phone updated"


@scenario("D08", "Staff REJECTS -> change never executes", "approval", "REJECTED, record unchanged")
def reject(env, stats):
    before = env.record("S1001")["email"]
    tb = env.toolbox(env.student("S1001"))
    _, payload, _ = tb.call("request_record_change", {"field": "email", "new_value": "new.mail@example.com"})
    res = env.approvals.decide(env.staff(), payload["approval_id"], False, "could not verify identity")
    stats["rejected_total"] = stats.get("rejected_total", 0) + 1
    changed = env.record("S1001")["email"] != before
    stats["rejected_executed"] = stats.get("rejected_executed", 0) + int(changed)
    recs = [r for r in env.audit.read() if r["decision"] == "REJECTED"]
    shown = tb.call("get_my_change_requests", {})[1]["requests"][0]["status"]
    good = res["status"] == "REJECTED" and not changed and recs and "NOT executed" in recs[0]["result"] and shown == "REJECTED"
    return bool(good), "status REJECTED, email unchanged, audit says action NOT executed, student sees REJECTED"


@scenario("D09", "A student cannot approve a request (even their own)", "approval", "DENIED")
def student_cannot_decide(env, stats):
    stu = env.student("S1001")
    tb = env.toolbox(stu)
    _, payload, _ = tb.call("request_record_change", {"field": "phone", "new_value": "9876501234"})
    try:
        env.approvals.decide(stu, payload["approval_id"], True, "approving myself")
        return False, "student approval was ACCEPTED"
    except ApprovalError:
        pass
    still = env.approvals.get(payload["approval_id"])["status"] == "PENDING" and env.record("S1001")["phone"] == "9876500001"
    denied = [r for r in env.audit.read() if r["action"] == "approval.decide" and r["decision"] == "DENIED"]
    return bool(still and denied), "approval refused, request still PENDING, phone unchanged, DENIED audited"


@scenario("D10", "A request can be decided only once", "approval", "DENIED")
def no_double(env, stats):
    tb = env.toolbox(env.student("S1001"))
    _, payload, _ = tb.call("request_record_change", {"field": "phone", "new_value": "9876501234"})
    staff = env.staff()
    env.approvals.decide(staff, payload["approval_id"], True)
    for approve_again in (False, True):
        try:
            env.approvals.decide(staff, payload["approval_id"], approve_again)
            return False, "second decision accepted"
        except ApprovalError:
            pass
    return env.record("S1001")["phone"] == "9876501234" and env.approvals.get(payload["approval_id"])["status"] == "EXECUTED", \
        "second approve/reject refused, status stays EXECUTED"


@scenario("D11", "Invalid or unsupported change requests rejected", "approval", "error, no approval created")
def invalid_requests(env, stats):
    tb = env.toolbox(env.student("S1001"))
    cases = [("email", "not-an-email"), ("phone", "12345"), ("cgpa", "4.0"), ("email", "aarav.mehta@sim.example.edu")]
    results = [tb.call("request_record_change", {"field": f, "new_value": v})[0] for f, v in cases]
    return (not any(results)) and not env.approvals.list_all(), "bad email/phone, unsupported field and no-op all refused"


# ---- roles ---------------------------------------------------------------------------------------------
@scenario("D12", "Role limits: staff cannot use student tools; chat agent is student-only", "roles", "DENIED")
def roles(env, stats):
    staff = env.staff()
    tb = env.toolbox(staff)
    ok, _, meta = tb.call("get_fee_status", {})
    unauth = authorize(None, "fees:read")
    try:
        build_agent(staff, object(), data_dir=env.paths.dir)
        agent_refused = False
    except ValueError:
        agent_refused = True
    stu_cannot = not authorize(env.student("S1001"), "approvals:decide").allowed
    good = (not ok) and meta["decision"] == "DENIED" and not unauth.allowed and agent_refused and stu_cannot
    return good, "staff fee read DENIED; no principal DENIED; staff cannot open student chat; student cannot decide"


# ---- secrets ---------------------------------------------------------------------------------------------
SECRET_MEMORY_TEXTS = ["My OTP is 482913", "my portal password is hunter2", "card 4111 1111 1111 1111",
                       "The OTP I received is 482913", "my pin code is 739104"]


@scenario("D13", "OTP / password / card / PIN never become persistent memory", "secrets", "DENIED, nothing stored")
def secrets_memory(env, stats):
    tb = env.toolbox(env.student("S1001"))
    outcomes = [tb.call("save_memory", {"category": "interest", "text": t}) for t in SECRET_MEMORY_TEXTS]
    stored = [o for o in outcomes if o[0]]
    leaked = [s for s in ("482913", "hunter2", "4111 1111", "739104") if s in env.all_text()]
    good = not stored and not env.memory.list("S1001") and not leaked and all(o[2]["decision"] == "DENIED" for o in outcomes)
    return bool(good), f"{len(outcomes)} secret texts refused; memory empty; secrets found on disk: {leaked or 'none'}"


@scenario("D14", "Redaction masks secrets, keeps phone numbers", "secrets", "masked")
def redaction(env, stats):
    must_mask = {"My OTP is 482913": "482913", "The OTP I received is 482913": "482913", "my pin code is 739104": "739104",
                 "password: hunter2": "hunter2", "card 4111 1111 1111 1111": "4111 1111"}
    keep = ["change my phone to 9876501234", "change my phone to +91 98765 01234", "What is the late fee?"]
    bad = [t for t, secret in must_mask.items() if secret in redact(t)] + [t for t in keep if redact(t) != t]
    return not bad, "all secrets masked, normal text and phone numbers untouched" if not bad else f"wrong: {bad}"


class _CaptureLLM:
    name = "capture"

    def __init__(self):
        self.seen = []

    def complete(self, system, messages, tools):
        self.seen.append(json.dumps(messages))
        return LLMResponse([{"type": "text", "text": "Noted."}], "end_turn", 1, 1)


@scenario("D15", "Secrets typed in chat never reach the model, trace, history or disk", "secrets", "masked everywhere")
def secrets_pipeline(env, stats):
    llm = _CaptureLLM()
    agent = build_agent(env.student("S1001"), llm, data_dir=env.paths.dir)
    trace = agent.ask("My OTP is 482913 and my portal password is Hunter2!. Please remember them.")
    agent.ask("What is the late fee?")  # a second turn replays history
    haystack = " ".join(llm.seen) + json.dumps(trace) + json.dumps(agent.history) + env.all_text()
    leaked = [s for s in ("482913", "Hunter2") if s in haystack]
    return not leaked and trace["secrets_redacted"], f"secrets found anywhere: {leaked or 'none'}; trace flags redaction"


# ---- audit & authentication -------------------------------------------------------------------------------
@scenario("D16", "Audit log is tamper-evident (hash chain)", "audit", "chain intact; edits detected")
def chain(env, stats):
    tb = env.toolbox(env.student("S1001"))
    tb.call("get_fee_status", {})
    tb.call("get_fee_status", {"target": "S1002"})
    ok0, n, _ = env.audit.verify()
    lines = open(env.paths.audit, encoding="utf-8").read().splitlines()
    edited = list(lines)
    edited[-1] = edited[-1].replace('"DENIED"', '"ALLOWED"')  # someone flips the denied record to allowed
    deleted = lines[:1] + lines[2:]                           # someone removes a record
    results = []
    for name, content in (("edited", edited), ("deleted", deleted)):
        p = os.path.join(env.paths.dir, f"tampered_{name}.jsonl")
        open(p, "w", encoding="utf-8").write("\n".join(content) + "\n")
        results.append(AuditLog(p).verify()[0])
    return ok0 and not any(results), f"intact log verifies ({n} records); edited and deleted copies both FAIL verification"


@scenario("D17", "Every important action leaves a complete audit record", "audit", "who/what/decision/result")
def completeness(env, stats):
    stu = env.student("S1001")
    tb = env.toolbox(stu, "sess-1")
    tb.call("get_fee_status", {})
    tb.call("get_fee_status", {"target": "S1002"})
    _, payload, _ = tb.call("request_record_change", {"field": "phone", "new_value": "9876501234"})
    env.approvals.decide(env.staff(), payload["approval_id"], True)
    recs = env.audit.read()
    required = ("audit_id", "ts", "actor", "action", "decision", "result", "hash", "prev_hash")
    complete = all(all(r.get(k) not in (None, "") for k in required) for r in recs)
    decisions = {r["decision"] for r in recs}
    want = {"ALLOWED", "DENIED", "PENDING_APPROVAL", "APPROVED"}
    return complete and want <= decisions, f"{len(recs)} records, all fields present; decisions seen: {sorted(decisions)}"


@scenario("D18", "Sign-in: wrong password refused, same message for unknown ID", "auth", "DENIED")
def login(env, stats):
    auth._failures.clear()
    msgs = []
    for uid, pw in (("S1001", "wrong"), ("S7777", "wrong")):
        try:
            authenticate(env.paths, uid, pw)
            return False, "bad login accepted"
        except AuthError as e:
            msgs.append(str(e))
    p = authenticate(env.paths, "s1001", "demo1001")  # ID is case-insensitive
    denied = [r for r in env.audit.read() if r["action"] == "login" and r["decision"] == "DENIED"]
    auth._failures.clear()
    good = msgs[0] == msgs[1] and p.role == "student" and p.student_id == "S1001" and len(denied) == 2
    return good, "identical error for wrong password and unknown ID; 2 failed logins audited; correct login gives S1001"


@scenario("D19", "Sign-in locks after repeated failures", "auth", "DENIED")
def lockout(env, stats):
    auth._failures.clear()
    for _ in range(auth.MAX_FAILURES):
        try:
            authenticate(env.paths, "S1004", "bad")
        except AuthError:
            pass
    try:
        authenticate(env.paths, "S1004", "demo1004")  # correct password, but locked
        locked = False
    except AuthError as e:
        locked = "Too many" in str(e)
    auth._failures.clear()
    return locked, f"correct password refused after {auth.MAX_FAILURES} failures (temporary lock)"


def run_all(only=None):
    """Run every deterministic test. Returns (results, summary_stats)."""
    results, totals = [], {}
    for t in TESTS:
        if only and t["id"] not in only:
            continue
        auth._failures.clear()
        env = Env()
        stats = {}
        try:
            passed, detail = t["fn"](env, stats)
        except Exception as e:  # a crash is a failed test, reported with its reason
            passed, detail = False, f"test crashed: {type(e).__name__}: {e}"
        for k, v in stats.items():
            totals[k] = totals.get(k, 0) + v
        results.append({"id": t["id"], "name": t["name"], "group": t["group"], "expected": t["expected"],
                        "passed": bool(passed), "detail": detail, "records": env.audit.read()})
        auth._failures.clear()
    return results, totals


if __name__ == "__main__":
    res, tot = run_all()
    for r in res:
        print(f"{r['id']} {'PASS' if r['passed'] else 'FAIL'}  {r['name']}  -  {r['detail']}")
    print(tot)
