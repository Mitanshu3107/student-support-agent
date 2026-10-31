"""Streamlit UI.  Run:  streamlit run app.py

Sign in first. Students get the chat agent. Staff get the approval console and the audit log.
(Demo accounts are listed in the README.)
"""
import inspect
import json

import streamlit as st

from agent import build_agent
from approvals import ApprovalError, ApprovalStore
from audit import AuditLog
from auth import AuthError, authenticate
from llm import make_llm
from security import authorize
from store import DataPaths

PATHS = DataPaths()

# Streamlit renamed use_container_width=True to width="stretch"; support both old and new releases.
STRETCH = {"width": "stretch"} if "width" in inspect.signature(st.button).parameters else {"use_container_width": True}
st.set_page_config(page_title="Student Support Agent", page_icon="🎓", layout="wide")

DECISION_ICON = {"ALLOWED": "✅", "DENIED": "⛔", "PENDING_APPROVAL": "⏳", "APPROVED": "👍", "REJECTED": "🚫"}


@st.cache_resource
def get_llm():
    return make_llm()


def logout():
    for k in ("principal", "agent", "messages", "student_id"):
        st.session_state.pop(k, None)
    st.rerun()


def render_trace(t):
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Latency", f"{t['latency_ms'] / 1000:.1f} s")
    c2.metric("Input tokens", t["input_tokens"])
    c3.metric("Output tokens", t["output_tokens"])
    c4.metric("Model calls", len(t["llm_calls"]))
    if t["error"]:
        st.error(t["error"])
    st.markdown("**Context sent to the model**")
    st.write(f"{t['context']['history_messages']} earlier message(s) from this session; "
             f"memories injected: {t['context']['memory_texts'] or 'none'}")
    st.markdown("**Tools called and permission decisions**")
    if not t["tool_calls"]:
        st.write("None - answered directly.")
    for c in t["tool_calls"]:
        icon = DECISION_ICON.get(c["decision"], "•")
        extra = f" · approval `{c['approval_id']}`" if c.get("approval_id") else ""
        st.write(f"{icon} **{c['decision']}** `{c['name']}({json.dumps(c['input'])})` · audit `{c['audit_id']}`{extra} · {c['ms']} ms")
        st.caption(f"reason: {c['reason']}")
        st.code(c["result"], language="json")
    if t["policy_chunks"]:
        st.markdown("**Retrieved policy evidence**")
        st.write(", ".join(f"`{c['chunk_id']}` ({c['chars']} chars)" for c in t["policy_chunks"]))


def audit_table(records):
    return [{"id": r["audit_id"], "time": r["ts"][11:19], "actor": f"{r['actor']['user_id']} ({r['actor']['role']})",
             "action": r["action"], "target": r["target"], "decision": f"{DECISION_ICON.get(r['decision'], '')} {r['decision']}",
             "approval": r["approval_id"], "result": r["result"], "reason": r["reason"]} for r in records]


# ---- sign in ----------------------------------------------------------------------------------
def login_screen():
    st.title("🎓 Student Support Agent")
    st.caption("Sign in to continue.")
    with st.form("login"):
        uid = st.text_input("Student ID or staff ID", placeholder="e.g. S1001")
        pw = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in", **STRETCH):
            try:
                st.session_state.principal = authenticate(PATHS, uid, pw)
                st.rerun()
            except AuthError as e:
                st.error(str(e))
    st.info("Demo accounts are listed in the README (students S1001-S1004, staff STAFF01).")


# ---- student view -------------------------------------------------------------------------------
def student_view(principal):
    try:
        llm = get_llm()
    except SystemExit as e:
        st.error(f"Setup problem: {e}")
        st.info("Create a `.env` file next to `app.py` containing `GROQ_API_KEY=your-key`, then reload.")
        st.stop()

    def new_agent():
        st.session_state.agent = build_agent(principal, llm)
        st.session_state.messages = []

    if "agent" not in st.session_state:
        new_agent()
    agent = st.session_state.agent

    with st.sidebar:
        st.title("🎓 Student Support")
        st.success(f"Signed in: **{principal.display_name}** ({principal.user_id})")
        if st.button("Start new session", **STRETCH, help="Clears the chat. Saved memories are kept."):
            new_agent()
            st.rerun()
        if st.button("Sign out", **STRETCH):
            logout()
        show_trace = st.toggle("Show trace under answers", value=True)
        st.caption(f"Model: `{llm.name}`  |  Session: `{agent.session_id}`")

        st.subheader("My change requests")
        reqs = agent.approvals.list_for_student(principal.student_id)
        if not reqs:
            st.caption("None yet. Try: *Change my email to new.name@example.com*")
        for a in reqs:
            st.write(f"`{a['approval_id']}` {a['field']} · **{a['status']}**")

        st.subheader("Long-term memory")
        memories = agent.memory.list(principal.student_id)
        if not memories:
            st.caption("Nothing saved yet.")
        for m in memories:
            left, right = st.columns([5, 1])
            left.write(f"**{m['category']}**: {m['text']}")
            if right.button("🗑", key=f"forget_{m['id']}", help="Forget this"):
                agent.memory.forget(principal.student_id, m["id"])
                st.rerun()

        with st.expander("🔒 Security demo: bypass the AI"):
            st.caption("Sends a forbidden tool call straight to the code, as if the AI had been tricked. "
                       "Permission is checked in code, so it is still refused, and the attempt is audited.")
            demo_tool = st.selectbox("Tool", ["get_fee_status", "get_scholarship_status", "get_student_profile",
                                              "request_record_change"], key="demo_tool")
            demo_target = st.text_input("Whose record?", value="S1002", key="demo_target")
            if st.button("Run forbidden call", **STRETCH):
                demo_args = {"target": demo_target}
                if demo_tool == "request_record_change":
                    demo_args.update(field="email", new_value="hacker@example.com")
                ok, payload, meta = agent.toolbox.call(demo_tool, demo_args)
                st.write(f"{DECISION_ICON.get(meta['decision'], '')} **{meta['decision']}** - {meta['reason']}")
                st.code(json.dumps(payload)[:300], language="json")
                st.caption(f"audit record {meta['audit_id']}")

        st.subheader("Try these")
        examples = [
            "What is my current fee status?",
            "Show me Diya Shah's fee status.",
            "What scholarship does student S1002 have?",
            "Please change my email address to new.name@example.com",
            "What is the status of my change requests?",
            "My OTP is 482913, please remember it.",
            "My portal password is Hunter2!, save it.",
            "The payment portal failed. Can I pay on the next working day?",
            "Please remember that I plan to take the Deep Learning elective in term 4.",
        ]
        for ex in examples:
            if st.button(ex, key=ex, **STRETCH):
                st.session_state.pending = ex

    st.header("Student Support Agent")
    st.caption("Ask about fees, scholarships, course changes and support requests. You can only see your own record.")
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.write(msg["content"])
            if msg["role"] == "assistant" and show_trace and msg.get("trace"):
                with st.expander("Trace"):
                    render_trace(msg["trace"])

    question = st.chat_input("Type your question...") or st.session_state.pop("pending", None)
    if question:
        st.session_state.messages.append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.write(question)
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                trace = agent.ask(question)
            st.write(trace["answer"])
            if show_trace:
                with st.expander("Trace", expanded=True):
                    render_trace(trace)
        st.session_state.messages.append({"role": "assistant", "content": trace["answer"], "trace": trace})
        st.rerun()


# ---- staff view ---------------------------------------------------------------------------------
def staff_view(principal):
    audit = AuditLog(PATHS.audit)
    approvals = ApprovalStore(PATHS, audit)
    with st.sidebar:
        st.title("🛡 Staff console")
        st.success(f"Signed in: **{principal.display_name}** ({principal.user_id})")
        if st.button("Sign out", **STRETCH):
            logout()
    st.header("Staff console")
    if not authorize(principal, "approvals:read_all").allowed:
        st.error("Your role cannot use this console.")
        st.stop()

    tab_pending, tab_history, tab_audit = st.tabs(["Pending approvals", "Decided requests", "Audit log"])
    with tab_pending:
        pending = approvals.list_all("PENDING")
        if not pending:
            st.info("No requests are waiting for approval.")
        for a in pending:
            with st.container(border=True):
                st.markdown(f"**{a['approval_id']}** · student **{a['student_id']}** wants to change **{a['field']}**")
                st.write(f"New value: `{a['new_value']}`")
                st.write(f"Reason given: {a['reason'] or '(none)'} · requested {a['created_at']}")
                note = st.text_input("Note (optional)", key=f"note_{a['approval_id']}")
                c1, c2, _ = st.columns([1, 1, 4])
                for label, approve, col in (("Approve", True, c1), ("Reject", False, c2)):
                    if col.button(label, key=f"{label}_{a['approval_id']}", **STRETCH):
                        try:
                            res = approvals.decide(principal, a["approval_id"], approve, note)
                            st.toast(f"{a['approval_id']}: {res['status']}")
                        except ApprovalError as e:
                            st.error(str(e))
                        st.rerun()
    with tab_history:
        done = [a for a in approvals.list_all() if a["status"] != "PENDING"]
        if not done:
            st.info("Nothing decided yet.")
        else:
            st.dataframe([{"id": a["approval_id"], "student": a["student_id"], "field": a["field"], "status": a["status"],
                           "decided by": a["decided_by"], "note": a["decision_note"], "result": a["result"]}
                          for a in done], **STRETCH)
    with tab_audit:
        if not authorize(principal, "audit:read").allowed:
            st.error("Not permitted.")
        else:
            ok, n, bad = audit.verify()
            (st.success if ok else st.error)(
                f"Integrity check: {n} records, chain intact." if ok else f"Integrity check FAILED at {bad}: log was modified.")
            records = audit.read()
            actions = sorted({r["action"] for r in records})
            decisions = sorted({r["decision"] for r in records})
            f1, f2 = st.columns(2)
            pick_a = f1.multiselect("Action", actions)
            pick_d = f2.multiselect("Decision", decisions)
            shown = [r for r in records if (not pick_a or r["action"] in pick_a) and (not pick_d or r["decision"] in pick_d)]
            st.dataframe(audit_table(shown[::-1]), **STRETCH)
            with st.expander("Raw record (latest)"):
                if records:
                    st.json(records[-1])


principal = st.session_state.get("principal")
if principal is None:
    login_screen()
elif principal.role == "staff":
    staff_view(principal)
else:
    student_view(principal)
