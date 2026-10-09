import json
import re
import sys
from collections import Counter

from llm import ask_json

CHUNK = 10  # bir çağırışda maksimum qayda sayı (reasoning tokenləri üçün yer qalsın)

COMMON = """You are an adversarial tester of corporate policies. You are given a policy's rules
and its full text. Find ways to defeat the rules using ONLY what the policy text says.

Output ONLY a JSON array. Each item:
{"rule_id": "R1", "policy_basis": "<exact words copied from the policy that make this possible>", "scenario": "..."}

STRICT GROUNDING RULES:
- Do NOT invent calendar dates, years, person names, company names, cities, vendors, or document types that are not in the policy. Use only generic roles ("the employee", "the department manager") and relative time ("day 0", "day 11").
- Use ONLY amounts and thresholds that appear in the policy, or simple arithmetic on them (e.g. "two receipts of 290 AZN"). Do not invent other prices.
- Do NOT assume forms, systems, signatures or procedures the policy does not mention.
- "policy_basis" must be ONE verbatim quote (a single contiguous passage, no "...") of the policy words being exploited. If you cannot quote any, skip the scenario.
- The scenario must satisfy the rule as literally written WITHOUT lying, forging, or hiding facts, and still defeat the rule's evident purpose. Ordinary real-world circumstances the policy is silent about (a weekend stay, meals provided by a host, several small claims) are allowed, as long as the employee reports them truthfully.
- Max 2 scenarios per rule, 1-3 sentences each. The 2 scenarios for one rule MUST exploit DIFFERENT weaknesses (never two splitting variants of the same rule). Skip a rule if no real exploit exists.
- For every approval rule, ask explicitly: "who approves, and can that person be the claimant?" If the policy never says the approver must be someone other than the claimant, that is a separate scenario from splitting.

WEAKNESS TYPES TO CHECK on every rule (policies usually fail by omission, not only by wording):
- a numeric limit applied per item with no cap on how many items, days, nights or claims;
- a deadline or time limit that does not say what it counts from, or a missing deadline altogether;
- an exception or waiver that one person grants with no criteria, evidence or maximum;
- one person who is both approver and beneficiary, or who decides alone with no second check;
- a benefit paid in full even when the need it covers is already met by someone else;
- an entitlement that is not tied to the purpose or dates it was granted for;
- a new request allowed while an earlier one is still open;
- a threshold that can be reached in pieces (splitting, repeating, combining);
- undefined key terms (necessary, reasonable, day, single expense);
- a person approving, authorising or deciding on an item that they themselves claimed, requested or benefit from (a manager approving their own expense);
- a no-proof or no-receipt allowance (below some amount) with no limit on how many such claims one person can submit, so many small claims add up;
- a flat allowance (per diem, daily rate) paid in full even when the thing it covers (meals, lodging, transport) is already provided free by the hotel, client, host or employer."""

PERSONAS = {
    "fraudster": COMMON + """

YOUR PERSONA: a fraudulent employee who deliberately steals money or abuses approvals.
Think: splitting amounts, self-approval, collusion with a colleague, double-dipping, repeating small claims, exploiting who approves whom.
For every approval rule, include one scenario where the approver is also the person who incurred the expense (for example the department manager or the Finance Director approving their own claim), unless the policy explicitly forbids it.""",
    "lazy": COMMON + """

YOUR PERSONA: a lazy, well-meaning employee who wants to skip effort and paperwork.
Think: shortcuts, missed deadlines with no consequence, steps nobody checks, approvals obtained trivially, open-ended obligations nobody enforces.""",
    "technicalist": COMMON + """

YOUR PERSONA: a legal-minded technicalist who exploits wording.
Think: vague words, undefined terms, unclear start points, missing definitions, gaps between articles, edge cases exactly at a threshold, things the policy simply never says.""",
}

YEAR_RE = re.compile(r"\b(19|20)\d{2}\b")


def _norm(s: str) -> str:
    return " ".join(re.sub(r"[^\w]+", " ", s.lower()).split())


def _basis_ok(basis: str, policy_norm: str) -> bool:
    parts = [_norm(p) for p in re.split(r"\.\.\.|…", basis)]
    parts = [p for p in parts if len(p) >= 4]
    return bool(parts) and all(p in policy_norm for p in parts)


def attack(rules: list[dict], policy_text: str = "") -> list[dict]:
    valid_ids = {r["id"] for r in rules}
    policy_norm = _norm(policy_text)
    policy_has_year = bool(YEAR_RE.search(policy_text))
    findings = []
    chunks = [rules[i:i + CHUNK] for i in range(0, len(rules), CHUNK)]

    for name, system in PERSONAS.items():
        for ci, chunk in enumerate(chunks, 1):
            rules_json = json.dumps(chunk, ensure_ascii=False, indent=2)
            user = (f"RULES TO ATTACK (only these rule_ids):\n{rules_json}\n\n"
                    f"FULL POLICY TEXT:\n{policy_text or '(not provided)'}")
            try:
                items = ask_json(system, user, max_tokens=3000, temperature=0.8)
            except Exception as e:
                print(f"[{name} #{ci}] XƏTA: {e}", file=sys.stderr)
                continue
            if not isinstance(items, list):
                print(f"[{name} #{ci}] XƏTA: cavab siyahı deyil", file=sys.stderr)
                continue

            chunk_ids = {r["id"] for r in chunk}
            drops = Counter()
            kept = 0
            for it in items:
                if not isinstance(it, dict):
                    drops["format"] += 1
                    continue
                rid = str(it.get("rule_id", "")).strip()
                scenario = str(it.get("scenario", "")).strip()
                basis = str(it.get("policy_basis", "")).strip()

                if rid not in valid_ids or rid not in chunk_ids or not scenario or not basis:
                    drops["rule_id/boş"] += 1
                    continue
                if policy_text and not _basis_ok(basis, policy_norm):
                    drops["sitat siyasətdə yoxdur"] += 1
                    continue
                if YEAR_RE.search(scenario) and not policy_has_year:
                    drops["uydurma il"] += 1
                    continue

                findings.append({
                    "rule_id": rid,
                    "attacker": name,
                    "policy_basis": basis,
                    "scenario": scenario,
                    "severity": "medium",
                    "verified": None,
                    "fix": "",
                    "estimated_loss_azn": 0,
                })
                kept += 1
            print(f"[{name} #{ci}] model {len(items)} verdi, {kept} qaldı, atılan: {dict(drops)}",
                  file=sys.stderr)
    return findings


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    from extract import SAMPLE, extract_rules

    text = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else SAMPLE
    rules = extract_rules(text)
    print(f"{len(rules)} qayda çıxarıldı", file=sys.stderr)
    out = attack(rules, text)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\nCəmi {len(out)} namizəd boşluq tapıldı")