"""Tests that need no model and no API key.   python tests/test_units.py

Runs the Assignment 1 unit tests (memory guard, retrieval, tool errors) and the whole Assignment 2
security suite (privacy, approvals, secrets, audit, sign-in). Exit code is non-zero if anything fails.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import security_suite as sec  # noqa: E402
from memory import MemoryStore, check_memory_text  # noqa: E402
from retrieval import PolicyRetriever  # noqa: E402

RETRIEVER = PolicyRetriever(sec.SRC.handbook)


def test_memory_guard_blocks_sensitive_and_temporary():
    for bad in ["My OTP is 482913", "card 4111 1111 1111 1111", "I have a medical condition",
                "call me on 9876543210", "I'm travelling today", "my password is hunter2"]:
        assert not check_memory_text(bad)[0], bad
    for good in ["I plan to take the Deep Learning elective in term 4", "I prefer short answers"]:
        assert check_memory_text(good)[0], good


def test_memory_persists_across_store_instances():
    env = sec.Env()
    path = env.paths.memory
    assert MemoryStore(path).add("S1", "goal", "I plan to take the Deep Learning elective")["stored"]
    reloaded = MemoryStore(path)
    assert reloaded.retrieve("S1", "which elective did I plan")[0]["text"].endswith("elective")
    assert not reloaded.add("S1", "goal", "I plan to take the Deep Learning elective")["stored"]  # duplicate
    assert reloaded.retrieve("S1", "what is the late fee") == []  # irrelevant memory is not injected


def test_retrieval_finds_right_section_and_abstains():
    assert RETRIEVER.search("payment portal failed, pay next working day")[0]["chunk_id"] == "handbook#3"
    assert RETRIEVER.search("conditions to renew a scholarship")[0]["chunk_id"] == "handbook#5"
    assert RETRIEVER.search("elective change after two weeks")[0]["chunk_id"] == "handbook#6"
    assert RETRIEVER.search("what is the hostel fee for next year") == []


def test_tools_handle_errors_without_raising():
    env = sec.Env()
    tb = env.toolbox(env.student("S1001"))
    assert tb.call("get_fee_status", {})[0] is True
    assert tb.call("nope", {})[0] is False
    assert tb.call("create_support_request", {"category": "fees", "summary": "short"})[0] is False
    assert tb.call("create_support_request", {"category": "bad", "summary": "long enough summary"})[0] is False
    assert tb.call("search_policy", {})[0] is False  # missing argument
    ok, p, meta = tb.call("create_support_request", {"category": "fees", "summary": "Portal failed, txn TXN1"})
    assert ok and p["ticket_id"].startswith("SR-") and meta["decision"] == "ALLOWED"
    down = env.toolbox(env.student("S1004"))
    assert down.call("get_fee_status", {})[0] is False  # fee system down
    from security import Principal
    ghost = env.toolbox(Principal("S9999", "student", "S9999", "Ghost"))
    assert "no student record" in ghost.call("get_scholarship_status", {})[1]["error"]


def test_security_suite():
    results, _ = sec.run_all()
    failed = [f"{r['id']} {r['name']}: {r['detail']}" for r in results if not r["passed"]]
    assert not failed, "\n".join(failed)


if __name__ == "__main__":
    bad = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn()
                print("ok  ", name)
            except AssertionError as e:
                bad += 1
                print("FAIL", name, "-", e)
    sys.exit(1 if bad else 0)
