"""Checks your Groq setup: python check_groq.py
Prints the models your key can use and makes one tiny test call, showing the real error if it fails."""
import os

from llm import GroqLLM, load_env

load_env()
llm = GroqLLM()
print(f"Base URL: {llm.client.base_url}   Model in use: {llm.model}")
try:
    ids = sorted(m.id for m in llm.client.models.list().data)
    print("Models available to your key:")
    for i in ids:
        print("  -", i)
except Exception as e:
    print(f"Could not list models: {type(e).__name__}: {e}")
try:
    r = llm.client.chat.completions.create(model=llm.model, max_tokens=5, messages=[{"role": "user", "content": "Say hi"}])
    print("Test call OK:", r.choices[0].message.content)
except Exception as e:
    print(f"Test call FAILED: {type(e).__name__}: {e}")
    print("Fix: set GROQ_MODEL in .env to one of the models listed above (or check your key/credits).")
