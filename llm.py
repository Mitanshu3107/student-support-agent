"""Model client: Groq (groq.com) through its OpenAI-compatible API.

The key is read from GROQ_API_KEY (environment variable or the .env file next to this file).
Optional: GROQ_MODEL (default openai/gpt-oss-120b) and GROQ_BASE_URL (default https://api.groq.com/openai/v1).

The agent works with Anthropic-style content blocks ({"type": "text" | "tool_use" | "tool_result"});
this client converts them to and from the OpenAI chat format, so the rest of the code is model-neutral.
"""
import json
import os
import time
from dataclasses import dataclass


@dataclass
class LLMResponse:
    content: list          # list of {"type": "text"|"tool_use", ...} dicts
    stop_reason: str
    input_tokens: int
    output_tokens: int
    waited_s: float = 0.0   # time spent waiting after rate-limit errors (not model time)


def load_env(path: str = None):
    """Minimal .env loader (KEY=value lines). Real environment variables win over the file."""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


class GroqLLM:
    RATE_LIMIT_TRIES = 4
    rate_limit_retries = 0
    def __init__(self, model: str = None):
        load_env()
        try:
            from openai import APIConnectionError, APITimeoutError, BadRequestError, OpenAI, RateLimitError
        except ImportError as e:
            raise SystemExit("Install the SDK first: pip install openai") from e
        key = os.environ.get("GROQ_API_KEY")
        if not key:
            raise SystemExit("GROQ_API_KEY not found. Put GROQ_API_KEY=... in the .env file next to chat.py.")
        self._RateLimitError = RateLimitError
        self._BadRequestError = BadRequestError
        self._Transient = (APITimeoutError, APIConnectionError)
        self.model = model or os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
        self.name = self.model
        self.client = OpenAI(api_key=key, base_url=os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
                             max_retries=int(os.environ.get("GROQ_MAX_RETRIES", "0")), timeout=60.0)

    @staticmethod
    def _to_openai_messages(system, messages):
        out = [{"role": "system", "content": system}]
        for m in messages:
            if isinstance(m["content"], str):
                out.append({"role": m["role"], "content": m["content"]})
            elif m["role"] == "assistant":
                text = "".join(b["text"] for b in m["content"] if b["type"] == "text")
                calls = [{"id": b["id"], "type": "function",
                          "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                         for b in m["content"] if b["type"] == "tool_use"]
                msg = {"role": "assistant", "content": text or None}
                if calls:
                    msg["tool_calls"] = calls
                out.append(msg)
            else:  # user turn made of tool_result blocks -> one 'tool' message each
                for b in m["content"]:
                    out.append({"role": "tool", "tool_call_id": b["tool_use_id"], "content": b["content"]})
        return out

    @staticmethod
    def _recover_tool_call(err):
        """Groq rejects a tool call whose arguments break the schema (for example an optional field sent as null)
        and returns the model's attempt in 'failed_generation'. If that is a plain {"name", "arguments"} object,
        use it with the null values dropped. Returns a tool_use block, or None when it cannot be recovered."""
        body = getattr(err, "body", None)
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            body = body["error"]
        raw = body.get("failed_generation") if isinstance(body, dict) else None
        if not isinstance(raw, str):
            return None
        try:
            call = json.loads(raw)
            name, args = call["name"], call.get("arguments") or {}
            if not isinstance(name, str) or not isinstance(args, dict):
                return None
        except (ValueError, KeyError, TypeError):
            return None
        args = {k: v for k, v in args.items() if v is not None}
        return {"type": "tool_use", "id": "recovered_" + os.urandom(4).hex(), "name": name, "input": args}

    def complete(self, system, messages, tools) -> LLMResponse:
        oa_tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                       "parameters": t["input_schema"]}} for t in tools]
        waited = 0.0
        transient = 0
        for attempt in range(1, self.RATE_LIMIT_TRIES + 1):
            try:
                resp = self.client.chat.completions.create(
                    model=self.model, messages=self._to_openai_messages(system, messages), tools=oa_tools, max_tokens=1024)
                break
            except self._BadRequestError as e:
                recovered = self._recover_tool_call(e)
                if recovered is None:
                    raise
                return LLMResponse([recovered], "tool_use", 0, 0, waited)
            except self._Transient:
                transient += 1  # network blip or timeout: nothing was executed yet, so retrying this call is safe
                if transient > 2:
                    raise
                time.sleep(3.0)
                waited += 3.0
            except self._RateLimitError:
                if attempt == self.RATE_LIMIT_TRIES:
                    raise
                wait = 15.0 * attempt
                time.sleep(wait)  # only this model call is retried; tools that already ran are never re-run
                waited += wait
                self.rate_limit_retries += 1
        msg = resp.choices[0].message
        content = []
        if msg.content:
            content.append({"type": "text", "text": msg.content})
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            args = {k: v for k, v in args.items() if v is not None}  # null means "not given"
            content.append({"type": "tool_use", "id": tc.id, "name": tc.function.name, "input": args})
        stop = "tool_use" if msg.tool_calls else "end_turn"
        return LLMResponse(content, stop, resp.usage.prompt_tokens, resp.usage.completion_tokens, waited)


def make_llm():
    return GroqLLM()
