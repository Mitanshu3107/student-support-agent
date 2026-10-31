"""Reset the demo to a clean start.   python reset_demo.py

Restores data/students.json from data/students.seed.json (approved changes are undone) and deletes the
runtime files: saved memories, tickets, approval requests and the audit log.
Run it before recording the demo or when you want a fresh run. It never touches the handbook or accounts.
"""
import os
import shutil

from store import DataPaths

paths = DataPaths()
seed = os.path.join(paths.dir, "students.seed.json")
shutil.copyfile(seed, paths.students)
removed = []
for p in (paths.memory, paths.tickets, paths.approvals, paths.audit):
    if os.path.exists(p):
        os.remove(p)
        removed.append(os.path.basename(p))
print(f"students.json restored from seed; removed: {', '.join(removed) or 'nothing'}")
