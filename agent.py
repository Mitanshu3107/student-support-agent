"""The agent loop: assemble a small context, let the model choose tools, feed results back, repeat
until the model answers (or the step limit is hit)."""
import json
import os
import time
import uuid

from approvals import ApprovalStore
from audit import AuditLog
from memory import MemoryStore
from retrieval import PolicyRetriever
from security import Principal, redact, redact_obj
from store import DataPaths
from tools import TOOL_SCHEMAS, ToolBox

SYSTEM_PROMPT = """You are the Student Support Agent for a PGDM programme. You help the signed-in student with fees, \
scholarships, course changes and support requests.

Rules:
- Student-specific facts (fee status, scholarship status, CGPA, attendance) must come from the tools. Never guess them.
- Policy answers must come from search_policy results. Cite the section title. If search_policy finds nothing relevant, \
say the handbook does not cover it, do not invent a rule, and offer a support request.
- If a tool returns an error, tell the student plainly what failed, do not invent data, and offer a support request.
- Answer simple greetings and general questions directly, without tools.
- Use save_memory only for lasting facts the student shares (programme, preferences, goals, interests). Never save \
temporary or sensitive information (passwords, OTPs, card/bank/ID numbers, health, finances, contact details), and \
never repeat such details back.
- Privacy: you serve ONE signed-in student and can only share that student's own data. If the student asks about \
another person, still call the relevant tool with `target` set to what they said: the system checks permission in \
code. If a tool result says access was denied, tell the student plainly that you can only help with their own record. \
Never reveal, guess or hint at another student's information.
- Sensitive changes: changing an email address or phone number needs staff approval. Use request_record_change, \
and ONLY say the change was made if a tool result says status EXECUTED. After the request tool succeeds, say the request \
is pending staff approval and nothing has changed yet. If the student asks about the status, use get_my_change_requests.
- The system masks credentials in messages before you see them (they appear as [REDACTED]). If you see that, tell the \
student their password/OTP/card number was removed and nothing was saved, and never ask them to type it again.
- Never save, repeat or echo credentials (passwords, OTPs, PINs, card numbers) the student types. Tell them not to \
share such details in chat and that nothing was saved.
- If the student asks you to remember something temporary or sensitive, do NOT say "I'll remember" or "I'll keep that in mind". \
Say plainly that you have not saved it to long-term memory (temporary or sensitive details are never stored) and, if it is \
only temporary, that you can use it for this conversation.
- Remembered preferences (for example short answers, or bullet points) apply to how you write EVERY reply. Follow them \
exactly: if the student prefers short answers, reply in one or two sentences with only the key figures.
- Be concise and friendly. Use "Rs" for amounts."""


class Agent:
    def __init__(self, principal: Principal, llm, retriever: PolicyRetriever, memory: MemoryStore, paths: DataPaths,
                 session_id=None, max_steps=6, history_turns=3):
        if principal is None or principal.role != "student" or not principal.student_id:
            raise ValueError("the chat agent serves a signed-in student")
        self.principal = principal
        self.student_id = principal.student_id
        self.llm = llm
        self.memory = memory
        self.paths = paths
        self.session_id = session_id or uuid.uuid4().hex[:8]
        self.audit = AuditLog(paths.audit)
        self.approvals = ApprovalStore(paths, self.audit)
        self.toolbox = ToolBox(principal, retriever, memory, paths, self.audit, self.approvals, self.session_id)
        self.max_steps = max_steps
        self.history_turns = history_turns
        self.history = []  # plain user/assistant text only - tool payloads from past turns are NOT replayed

    # ---- context selection ------------------------------------------------------------------------
    def build_context(self, question: str):
        """Return (system_prompt, messages, injected_memories). Only the current question, a short
        text-only history window and the memories relevant to this question are sent."""
        memories = self.memory.retrieve(self.student_id, question, k=3)
        system = SYSTEM_PROMPT + f"\n\nSigned-in student: {self.principal.display_name} (ID {self.student_id})"
        if memories:
            system += "\n\nRemembered about this student (from earlier sessions; always follow preferences, use other facts only if relevant):\n"
            system += "\n".join(f"- [{m['id']}] ({m['category']}) {m['text']}" for m in memories)
        window = self.history[-2 * self.history_turns:]
        return system, window + [{"role": "user", "content": question}], memories

    # ---- one turn ------------------------------------------------------------------------------------
    def ask(self, question: str) -> dict:
        t_start = time.perf_counter()
        raw_question = question
        question = redact(raw_question)  # secrets (OTP, password, card number) never reach the model, traces or history
        system, messages, memories = self.build_context(question)
        trace = {
            "student_id": self.student_id, "session_id": self.session_id, "question": question, "secrets_redacted": question != raw_question,
            "context": {"history_messages": len(messages) - 1, "memory_ids": [m["id"] for m in memories],
                        "memory_texts": [m["text"] for m in memories], "system_chars": len(system)},
            "llm_calls": [], "tool_calls": [], "policy_chunks": [], "error": None,
        }
        answer = None
        for step in range(1, self.max_steps + 1):
            t0 = time.perf_counter()
            try:
                resp = self.llm.complete(system, messages, TOOL_SCHEMAS)
            except Exception as e:  # network / API failure: degrade gracefully
                trace["error"] = f"LLM call failed: {type(e).__name__}: {e}"
                answer = "Sorry, I'm having trouble reaching the assistant service right now. Please try again shortly."
                break
            trace["llm_calls"].append({
                "step": step, "ms": round((time.perf_counter() - t0) * 1000, 1),
                "input_tokens": resp.input_tokens, "output_tokens": resp.output_tokens, "waited_s": resp.waited_s,
            })
            messages.append({"role": "assistant", "content": resp.content})
            tool_uses = [b for b in resp.content if b["type"] == "tool_use"]
            if not tool_uses:
                answer = "".join(b["text"] for b in resp.content if b["type"] == "text").strip()
                break
            results = []
            for tu in tool_uses:
                t1 = time.perf_counter()
                ok, payload, meta = self.toolbox.call(tu["name"], tu["input"])
                chunk_ids = [c["chunk_id"] for c in payload.get("results", [])] if ok and tu["name"] == "search_policy" else []
                if tu["name"] == "search_policy" and ok:
                    trace["policy_chunks"].extend(
                        {"chunk_id": c["chunk_id"], "chars": len(c["text"])} for c in payload["results"])
                trace["tool_calls"].append({
                    "step": step, "name": tu["name"], "input": redact_obj(tu["input"]), "ok": ok,
                    "decision": meta["decision"], "audit_id": meta["audit_id"], "approval_id": meta["approval_id"],
                    "reason": meta["reason"],
                    "result": json.dumps(payload)[:240], "chunk_ids": chunk_ids,
                    "ms": round((time.perf_counter() - t1) * 1000, 1),
                })
                results.append({"type": "tool_result", "tool_use_id": tu["id"], "content": json.dumps(payload),
                                "is_error": not ok})
            messages.append({"role": "user", "content": results})
        if answer is None:
            answer = ("I wasn't able to finish working that out. I can raise a support request so a staff member "
                      "can help - would you like that?")
            trace["error"] = f"stopped after {self.max_steps} steps"

        if trace["error"] is None:  # a failed turn (API error, step limit) is not added to the conversation
            # secrets are removed before the turn is kept as conversation history
            self.history += [{"role": "user", "content": question}, {"role": "assistant", "content": redact(answer)}]
        trace["answer"] = answer
        waited = sum(c.get("waited_s", 0) for c in trace["llm_calls"])
        trace["rate_limit_wait_s"] = waited
        trace["latency_ms"] = round((time.perf_counter() - t_start - waited) * 1000, 1)  # excludes rate-limit waits
        trace["input_tokens"] = sum(c["input_tokens"] for c in trace["llm_calls"])
        trace["output_tokens"] = sum(c["output_tokens"] for c in trace["llm_calls"])
        return trace


def build_agent(principal: Principal, llm, session_id=None, data_dir=None):
    """Build an agent for an already-authenticated student. All state lives under data_dir."""
    paths = DataPaths(data_dir)
    retriever = PolicyRetriever(paths.handbook)
    memory = MemoryStore(paths.memory)
    return Agent(principal, llm, retriever, memory, paths, session_id=session_id)
