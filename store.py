"""Where every data file lives. One folder = one 'deployment', so the evaluation can run against a
throw-away copy of data/ without touching the real files."""
import json
import os
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
_LOCK = threading.RLock()  # one process-wide lock for read-modify-write on the JSON files


class DataPaths:
    def __init__(self, data_dir: str = None):
        self.dir = data_dir or os.path.join(HERE, "data")
        self.handbook = os.path.join(self.dir, "handbook.md")
        self.students = os.path.join(self.dir, "students.json")
        self.users = os.path.join(self.dir, "users.json")
        self.memory = os.path.join(self.dir, "memory.json")
        self.tickets = os.path.join(self.dir, "tickets.json")
        self.approvals = os.path.join(self.dir, "approvals.json")
        self.audit = os.path.join(self.dir, "audit.jsonl")


def read_json(path: str, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path: str, data):
    """Write to a temp file then rename, so a crash never leaves a half-written file."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def lock():
    return _LOCK
