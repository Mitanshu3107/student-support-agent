"""Persistent long-term memory (JSON file, keyed by student ID).

What is stored: durable, useful facts (programme/specialisation, preferences, goals, interests).
What is refused: sensitive data (credentials, card/ID numbers, health, finances, contact details)
and temporary/one-off statements. The guard runs in code, so it protects the store even if the
model wrongly decides to save something.
"""
import json
import os
import re
import tempfile
from datetime import datetime, timezone

from retrieval import tokenize

CATEGORIES = ("programme", "preference", "goal", "interest")

SENSITIVE_PATTERNS = [
    (r"\b(password|passcode|otp|pin|cvv|cvc|secret)\b", "credentials"),
    (r"(?:\d[ -]?){12,19}", "card, bank or ID number"),
    (r"\b(aadhaar|aadhar|passport|ssn|pan (card|number)|account (number|no))\b", "identity or bank detail"),
    (r"\b(diagnos\w*|medical|illness|depress\w*|anxiety|therapy|medication|disabilit\w*|pregnan\w*)\b", "health information"),
    (r"\b(salary|income|loan|debt)\b", "financial detail"),
    (r"[\w.+-]+@[\w-]+\.[\w.]+|\b\d{10}\b", "contact detail (already on your record)"),
]
TEMPORARY_PATTERN = (
    r"\b(today|tonight|tomorrow|yesterday|right now|at the moment|for now|"
    r"this (morning|afternoon|evening|week|weekend))\b"
)


def check_memory_text(text: str):
    """Return (ok, reason). reason explains a refusal."""
    lowered = text.lower()
    for pattern, label in SENSITIVE_PATTERNS:
        if re.search(pattern, lowered):
            return False, f"sensitive information ({label}) is never stored"
    if re.search(TEMPORARY_PATTERN, lowered):
        return False, "it looks temporary or one-off, so it is not stored as long-term memory"
    if len(text.strip()) < 8:
        return False, "it is too short to be a useful memory"
    return True, ""


class MemoryStore:
    def __init__(self, path: str):
        self.path = path
        self._data = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._data = json.load(f)

    def _save(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(self.path)), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)
        os.replace(tmp, self.path)

    def list(self, student_id: str) -> list:
        return list(self._data.get(student_id, []))

    def add(self, student_id: str, category: str, text: str, session_id: str = "") -> dict:
        """Try to store a memory. Always returns a dict with 'stored' and a 'reason' when refused."""
        text = " ".join(text.split())[:200]
        if category not in CATEGORIES:
            return {"stored": False, "reason": f"category must be one of {list(CATEGORIES)}"}
        ok, reason = check_memory_text(text)
        if not ok:
            return {"stored": False, "reason": reason}
        items = self._data.setdefault(student_id, [])
        for item in items:
            if item["text"].lower() == text.lower():
                return {"stored": False, "reason": "already remembered", "id": item["id"]}
        item = {
            "id": f"m{len(items) + 1:03d}",
            "category": category,
            "text": text,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_session": session_id,
        }
        items.append(item)
        self._save()
        return {"stored": True, "id": item["id"], "text": text}

    def forget(self, student_id: str, item_id: str) -> bool:
        items = self._data.get(student_id, [])
        kept = [i for i in items if i["id"] != item_id]
        if len(kept) == len(items):
            return False
        self._data[student_id] = kept
        self._save()
        return True

    def retrieve(self, student_id: str, query: str, k: int = 3) -> list:
        """Context selection for memory: preference items always (they shape the reply style, max 2),
        other items only when they share content words with the question."""
        q_terms = set(tokenize(query))
        scored, prefs = [], []
        for item in self.list(student_id):
            overlap = len(q_terms & set(tokenize(item["text"])))
            if item["category"] == "preference":
                prefs.append(item)
            elif overlap:
                scored.append((overlap, item))
        scored.sort(key=lambda s: -s[0])
        return prefs[:2] + [i for _, i in scored[: max(0, k - len(prefs[:2]))]]
