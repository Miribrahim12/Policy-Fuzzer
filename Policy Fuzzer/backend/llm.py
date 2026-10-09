import json
import os
import re
import sys
import time

from dotenv import load_dotenv

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except Exception:
        pass

load_dotenv()
PROVIDER = os.getenv("PROVIDER", "groq").lower()
MODEL = os.getenv("MODEL", "openai/gpt-oss-120b")
REASONING = os.getenv("REASONING_EFFORT", "low")

_client = None


def _get_client():
    global _client
    if _client is None:
        if PROVIDER == "groq":
            from groq import Groq
            _client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        else:
            from anthropic import Anthropic
            _client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _client


def _call(system: str, user: str, max_tokens: int, temperature: float) -> str:
    c = _get_client()
    if PROVIDER == "groq":
        kwargs = dict(
            model=MODEL,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        if "gpt-oss" in MODEL and REASONING:
            kwargs["reasoning_effort"] = REASONING
        try:
            r = c.chat.completions.create(**kwargs)
        except Exception as e:
            if "reasoning_effort" in str(e).lower() and "reasoning_effort" in kwargs:
                kwargs.pop("reasoning_effort")
                r = c.chat.completions.create(**kwargs)
            else:
                raise
        ch = r.choices[0]
        if ch.finish_reason == "length":
            print(f"[llm] cavab max_tokens={max_tokens} limitində kəsildi", file=sys.stderr)
        return ch.message.content or ""
    r = c.messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        temperature=temperature,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return r.content[0].text


def _retry_after(msg: str, default: float) -> float:
    # Groq: "Please try again in 7.5s" və ya "in 1m12.3s"
    m = re.search(r"try again in (?:(\d+)m)?([\d.]+)s", msg)
    if m:
        return int(m.group(1) or 0) * 60 + float(m.group(2)) + 1.0
    return default


def ask(system: str, user: str, max_tokens: int = 3000, temperature: float = 0.3) -> str:
    time.sleep(float(os.getenv("CALL_GAP", "1.5")))  # çağırışlar arası fasilə
    for attempt in range(8):
        try:
            out = _call(system, user, max_tokens, temperature)
            if not out.strip() and max_tokens < 8000:
                print("[llm] boş cavab, max_tokens artırılıb təkrar cəhd", file=sys.stderr)
                out = _call(system, user, min(max_tokens * 2, 8000), temperature)
            return out
        except Exception as e:
            msg = str(e).lower()
            if "429" in msg or "rate" in msg or "overloaded" in msg:
                wait = min(_retry_after(msg, 2 ** attempt * 3), 90)
                print(f"[llm] limit, {wait:.0f} san gözləyirəm (cəhd {attempt + 1}/8)", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
    raise RuntimeError("Limit aşıldı, bir az gözləyib yenidən cəhd et")


def parse_json(text: str):
    text = re.sub(r"```(?:json)?", "", text).strip()
    starts = [i for i in (text.find("["), text.find("{")) if i != -1]
    if not starts:
        raise ValueError("JSON tapılmadı")
    start = min(starts)
    end = max(text.rfind("]"), text.rfind("}"))
    return json.loads(text[start : end + 1])


def ask_json(system: str, user: str, max_tokens: int = 3000,
             temperature: float = 0.3, retries: int = 1):
    last_err = None
    for _ in range(retries + 1):
        raw = ask(system, user, max_tokens, temperature)
        try:
            return parse_json(raw)
        except Exception as e:
            last_err = e
            user += "\n\nPrevious answer was invalid JSON. Return ONLY valid JSON."
    raise last_err