import json
import os
import sys

from attack import attack
from extract import extract_rules
from judge import judge
from llm import ask_json

SEV = {"high": 3, "medium": 2, "low": 1}
CHUNK_ITEMS = 25

DEDUPE_SYSTEM = """You group duplicate findings from a policy audit. All findings in one call concern the SAME rule.
Two findings are duplicates ONLY if they exploit the same mechanism of the same weakness, even if names, dates and amounts differ.
Findings that use DIFFERENT mechanisms are never duplicates, for example:
- splitting an amount into pieces
- self-approval (approver is the claimant)
- a missing cap on how many items, days, nights or claims
- a missing or unclear deadline or start point
- an undefined term or unit (such as what counts as a 'day')
- a benefit paid in full although the need it covers is already met by someone else
- an unlimited waiver or discretion
- a new request allowed while an earlier one is open
If in doubt, keep them SEPARATE: wrongly merging loses a real loophole, keeping a duplicate costs only one extra line.
Return ONLY a JSON array of groups, each group a list of finding indices.
Every index must appear exactly once. Example: [[0,3],[1],[2,5]]"""


def _rule_num(f: dict) -> int:
    try:
        return int(str(f["rule_id"])[1:])
    except Exception:
        return 0


def _groups(items: list[dict]) -> list[list[int]]:
    n = len(items)
    if n < 2:
        return [[i] for i in range(n)]
    payload = [
        {"i": i, "rule": f["rule_id"], "scenario": f["scenario"][:260]}
        for i, f in enumerate(items)
    ]
    try:
        raw = ask_json(DEDUPE_SYSTEM, json.dumps(payload, ensure_ascii=False),
                       max_tokens=1500, temperature=0.0)
    except Exception as e:
        print(f"[dedupe] xəta: {e}", file=sys.stderr)
        return [[i] for i in range(n)]
    seen, out = set(), []
    for g in raw if isinstance(raw, list) else []:
        if not isinstance(g, list):
            continue
        idx = [i for i in g if isinstance(i, int) and 0 <= i < n and i not in seen]
        if idx:
            seen.update(idx)
            out.append(idx)
    out.extend([i] for i in range(n) if i not in seen)
    return out


def _merge(members: list[dict]) -> dict:
    best = max(members, key=lambda f: (SEV.get(f["severity"], 0), f["estimated_loss_azn"]))
    item = dict(best)
    item["duplicates"] = len(members) - 1 + sum(m.get("duplicates", 0) for m in members)
    atk = set()
    for m in members:
        atk.update(m.get("attackers") or [m["attacker"]])
    item["attackers"] = sorted(atk)
    return item


def dedupe(findings: list[dict]) -> list[dict]:
    """Yalnız eyni qayda daxilində birləşdirir (çarpaz-qayda birləşmə real boşluqları itirirdi)."""
    if not findings:
        return []

    by_rule: dict[str, list[dict]] = {}
    for f in sorted(findings, key=_rule_num):
        by_rule.setdefault(f["rule_id"], []).append(f)

    final = []
    for items in by_rule.values():
        for s in range(0, len(items), CHUNK_ITEMS):
            ch = items[s:s + CHUNK_ITEMS]
            for g in _groups(ch):
                final.append(_merge([ch[j] for j in g]))

    final.sort(key=lambda x: (-SEV.get(x["severity"], 0), -x["estimated_loss_azn"]))
    return final


def build_stats(candidates: int, counts: dict, valid_n: int, unique: list[dict]) -> dict:
    return {
        "candidates": candidates,
        "verdicts": counts,
        "valid_before_dedupe": valid_n,
        "unique_loopholes": len(unique),
        "loss_per_occurrence_azn": sum(f["estimated_loss_azn"] for f in unique),
    }


def run_stream(text: str):
    rules = extract_rules(text)
    yield {"stage": "rules", "rules": rules}

    candidates = attack(rules, text)
    yield {"stage": "candidates", "count": len(candidates)}

    judged = judge(rules, candidates)
    counts = {}
    for f in judged:
        counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
    yield {"stage": "judged", "counts": counts}

    valid = [f for f in judged if f["verified"]]
    unique = dedupe(valid)
    for f in unique:
        yield {"stage": "finding", "finding": f}

    stats = build_stats(len(candidates), counts, len(valid), unique)
    yield {"stage": "done", "result": {"rules": rules, "findings": unique, "stats": stats}}


def run(text: str) -> dict:
    result = None
    for ev in run_stream(text):
        if ev["stage"] == "done":
            result = ev["result"]
    return result


if __name__ == "__main__":
    from extract import SAMPLE

    text = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else SAMPLE
    for ev in run_stream(text):
        st = ev["stage"]
        if st == "rules":
            print(f"{len(ev['rules'])} qayda çıxarıldı")
        elif st == "candidates":
            print(f"{ev['count']} namizəd, hakim yoxlayır...")
        elif st == "judged":
            print("Hökmlər:", ev["counts"])
        elif st == "finding":
            f = ev["finding"]
            print(f"\n[{f['severity'].upper()}] {f['rule_id']} x{f['duplicates']+1} ({', '.join(f['attackers'])})")
            print(f"  {f['scenario'][:130]}...")
            print(f"  Düzəliş: {f['fix']}  | məruz qalma: {f['estimated_loss_azn']} AZN")
        elif st == "done":
            result = ev["result"]
            print("\nSTATISTIKA:", json.dumps(result["stats"], ensure_ascii=False, indent=2))
            cache = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cache")
            os.makedirs(cache, exist_ok=True)
            with open(os.path.join(cache, "last_run.json"), "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2)
            print("cache/last_run.json yazıldı")