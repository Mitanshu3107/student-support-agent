"""Terminal chat (students only).   python chat.py --user S1001 [--trace]

You are asked for the password (demo accounts are in the README). Commands:
  /trace  last run's trace   /memory  list saved memories   /forget <id>  delete one
  /requests  your change requests   /new  new session (memory is kept)   /quit
Staff approve requests in the web app (streamlit run app.py).
"""
import argparse
import getpass
import json

from agent import build_agent
from auth import AuthError, authenticate
from llm import make_llm
from store import DataPaths


def print_trace(t):
    print(f"  context : {t['context']['history_messages']} history msgs, memories injected: {t['context']['memory_ids'] or 'none'}")
    for c in t["tool_calls"]:
        print(f"  tool    : {c['name']}({json.dumps(c['input'])[:70]}) -> {c['decision']} (audit {c['audit_id']}"
              f"{', approval ' + c['approval_id'] if c.get('approval_id') else ''}) {c['chunk_ids'] or ''}")
    if not t["tool_calls"]:
        print("  tool    : (none - answered directly)")
    if t["error"]:
        print(f"  ERROR   : {t['error']}")
    print(f"  cost    : {t['latency_ms']} ms, {t['input_tokens']} in / {t['output_tokens']} out tokens, "
          f"{len(t['llm_calls'])} model call(s)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default="S1001", help="your student ID")
    ap.add_argument("--trace", action="store_true", help="print a trace after every answer")
    args = ap.parse_args()

    paths = DataPaths()
    try:
        principal = authenticate(paths, args.user, getpass.getpass(f"Password for {args.user}: "))
    except AuthError as e:
        raise SystemExit(str(e))
    if principal.role != "student":
        raise SystemExit("Staff accounts use the web app: streamlit run app.py")

    llm = make_llm()
    agent = build_agent(principal, llm)
    last = None
    print(f"Signed in as {principal.display_name} ({principal.user_id}) - model: {llm.name}. Type /quit to exit.")
    while True:
        try:
            text = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not text:
            continue
        if text == "/quit":
            break
        if text == "/new":
            agent = build_agent(principal, llm)
            print(f"[new session {agent.session_id}; saved memories are kept]")
            continue
        if text == "/trace":
            print_trace(last) if last else print("[no run yet]")
            continue
        if text == "/memory":
            for m in agent.memory.list(principal.student_id) or [{"id": "-", "category": "-", "text": "(empty)"}]:
                print(f"  [{m['id']}] ({m['category']}) {m['text']}")
            continue
        if text == "/requests":
            for a in agent.approvals.list_for_student(principal.student_id) or []:
                print(f"  {a['approval_id']} {a['field']} -> {a['status']}")
            continue
        if text.startswith("/forget "):
            print("[deleted]" if agent.memory.forget(principal.student_id, text.split()[1]) else "[no such memory id]")
            continue
        last = agent.ask(text)
        print(f"\nagent> {last['answer']}")
        if last["error"]:
            print(f"[details] {last['error']}")
        if args.trace:
            print_trace(last)


if __name__ == "__main__":
    main()
