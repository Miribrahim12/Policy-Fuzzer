import sys

from llm import ask_json

SYSTEM = """You extract rules from corporate policy documents.
Return ONLY a JSON array. No commentary.
Each item: {"id": "R1", "text": "...", "type": "limit|approval|condition|deadline"}

STRICT REQUIREMENTS:
- Each rule must be a COMPLETE, self-contained sentence that makes sense alone. Never output a fragment like "Expenses above 500 AZN".
- Do NOT duplicate. If one sentence in the source contains one obligation, output it exactly once.
- Split a sentence into several rules ONLY if it contains clearly separate obligations. Otherwise keep it as one rule.
- Preserve exact numbers, roles, and wording from the source. Keep vague words like "when necessary", "reasonable", "may" verbatim; do not clean them up.
- type: limit = numeric cap/threshold, approval = who must sign off, condition = if/when requirement or permission, deadline = time constraint.
- Number ids sequentially: R1, R2, ..."""

VALID_TYPES = {"limit", "approval", "condition", "deadline"}


def extract_rules(text: str) -> list[dict]:
    data = ask_json(SYSTEM, f"POLICY:\n{text}")
    rules = []
    for i, r in enumerate(data, 1):
        rtype = r.get("type", "condition")
        rules.append({
            "id": f"R{i}",
            "text": str(r.get("text", "")).strip(),
            "type": rtype if rtype in VALID_TYPES else "condition",
        })
        seen, unique = set(), []
    for r in rules:
        key = r["text"].lower().rstrip(". ")
        # başqa qaydanın içində tam yerləşən qısa fraqmentləri də at
        if not r["text"] or key in seen:
            continue
        if any(key != o and key in o for o in (x["text"].lower().rstrip(". ") for x in rules)):
            continue
        seen.add(key)
        unique.append(r)
    for i, r in enumerate(unique, 1):
        r["id"] = f"R{i}"
    return unique


SAMPLE = """Article 1. Expenses above 500 AZN require written approval from the department manager.
Article 2. Receipts must be submitted within 10 days. Late receipts may be rejected.
Article 3. Managers may approve travel expenses when necessary.
Article 4. Per diem is 60 AZN per day for domestic travel."""

if __name__ == "__main__":
    if len(sys.argv) > 1:
        text = open(sys.argv[1], encoding="utf-8").read()
    else:
        text = SAMPLE
    import json
    print(json.dumps(extract_rules(text), ensure_ascii=False, indent=2))