"""(Re)create data/users.json with the DEMO accounts.   python make_users.py

Demo credentials (assignment use only - change them before any real use):
  S1001 / demo1001    S1002 / demo1002    S1003 / demo1003    S1004 / demo1004    STAFF01 / staff-demo
"""
import json
import os

from auth import ITERATIONS, hash_password
from store import DataPaths

ACCOUNTS = [
    ("S1001", "student", "S1001", "Aarav Mehta", "demo1001"),
    ("S1002", "student", "S1002", "Diya Shah", "demo1002"),
    ("S1003", "student", "S1003", "Rohan Iyer", "demo1003"),
    ("S1004", "student", "S1004", "Meera Kulkarni", "demo1004"),
    ("STAFF01", "staff", None, "Registrar Office", "staff-demo"),
]

if __name__ == "__main__":
    paths = DataPaths()
    users = {}
    for uid, role, sid, name, pw in ACCOUNTS:
        salt = os.urandom(16).hex()
        users[uid] = {"role": role, "student_id": sid, "display_name": name, "salt": salt,
                      "iterations": ITERATIONS, "hash": hash_password(pw, salt)}
    with open(paths.users, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    print(f"wrote {paths.users} with {len(users)} demo accounts")
