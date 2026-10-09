import json
import os
import sys

from llm import ask_json

SYSTEM = """You are a strict, skeptical policy auditor. For each attack scenario decide whether it
reveals a genuine LOOPHOLE IN THE POLICY ITSELF.

verdict (pick exactly one):
- "valid": the scenario is achievable by following the literal wording of the rules (no lying, no forged or falsified documents or timestamps, no hidden facts) AND it defeats the evident purpose of the rule(s). The remedy would be to change the policy text.
    Gaps count. A missing limit, count cap, deadline, definition, start point or criterion that lets someone obtain money or skip a control the rules evidently intend is a genuine loophole, even though the policy "does not forbid" it.
        Ordinary real-world circumstances that the policy does not mention (a weekend extension, meals provided by a hotel, client or host, several small claims, an approver who is also the claimant) are fine, provided the employee reports them truthfully. A rule that requires approval does not prevent self-approval unless it says the approver must be a different person.
    NOT valid if it only works because someone states something untrue, or if it depends on a specific form, system or procedure the policy never mentions.
- "forgery": it needs forged, falsified or fabricated documents/dates/timestamps, plain lying, or a false statement of fact (e.g. claiming days that were not traveled, claiming a trip that did not happen). Also forgery: the scenario needs the employee to record, label or report something differently from what actually happened (e.g. recording a business-class ticket as economy, listing fictitious clients, claiming nights not stayed). That is fraud, not a policy flaw.
- "not_a_loophole": a rule actually prevents it, or it misreads the rule, or it does not defeat the rule's purpose, or it is immaterial. Also not_a_loophole: it relies on an older or hypothetical version of the policy, or on a future policy change.

Be strict about lying and invented procedures, but do not reject a scenario merely because the policy is silent: silence is exactly what a loophole is. Judge only what the rules say.

For "valid" items set:
- severity: "high" (large sums, fully bypasses a control, or easily repeatable), "medium", or "low"
- fix: ONE concrete sentence of replacement policy wording that closes the loophole
- estimated_loss_azn: integer, AZN of exposure per single occurrence derived from numbers in the scenario; 0 if it cannot be derived.
    Base it only on amounts and quantities stated in the policy. If the scenario needs an assumed quantity (e.g. a number of days), use the smallest plausible case and never mark severity "high" solely because of an assumed large quantity.
For other verdicts: severity "low", fix "", estimated_loss_azn 0.

Return ONLY a JSON array, one item per scenario:
[{"i": 0, "verdict": "valid", "reason": "one sentence", "severity": "high", "fix": "...", "estimated_loss_azn": 450}]"""


def _to_int(x) -> int:
    try:
        return max(0, int(float(x)))
    except Exception:
        return 0


def judge(rules: list[dict], findings: list[dict], chunk_size: int = 9) -> list[dict]:
    rules_json = json.dumps(rules, ensure_ascii=False)
    rule_text = {r["id"]: r["text"] for r in rules}
    result = []

    for start in range(0, len(findings), chunk_size):
        chunk = findings[start : start + chunk_size]
        payload = [
            {"i": i, "rule": rule_text.get(f["rule_id"], ""), "scenario": f["scenario"]}
            for i, f in enumerate(chunk)
        ]
        user = f"ALL RULES:\n{rules_json}\n\nSCENARIOS TO JUDGE:\n{json.dumps(payload, ensure_ascii=False)}"
        try:
            verdicts = ask_json(SYSTEM, user, max_tokens=6000, temperature=0.0)
            vmap = {int(v["i"]): v for v in verdicts if "i" in v}
        except Exception as e:
            print(f"[judge] xəta: {e}", file=sys.stderr)
            vmap = {}

        for i, f in enumerate(chunk):
            v = vmap.get(i)
            g = dict(f)
            if v is None:
                g.update(verified=False, verdict="judge_failed", reason="Judge returned no verdict")
            else:
                ok = v.get("verdict") == "valid"
                sev = v.get("severity", "low")
                g.update(
                    verified=ok,
                    verdict=v.get("verdict", "not_a_loophole"),
                    reason=str(v.get("reason", "")).strip(),
                    severity=sev if sev in ("low", "medium", "high") else "low",
                    fix=str(v.get("fix", "")).strip() if ok else "",
                    estimated_loss_azn=_to_int(v.get("estimated_loss_azn")) if ok else 0,
                )
            result.append(g)
    return result


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    from attack import attack
    from extract import SAMPLE, extract_rules

    text = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else SAMPLE
    rules = extract_rules(text)
    print(f"{len(rules)} qayda çıxarıldı, hücum başlayır...")
    candidates = attack(rules, text)
    print(f"{len(candidates)} namizəd tapıldı, hakim yoxlayır...")
    judged = judge(rules, candidates)

    out = {"rules": rules, "findings": judged}
    cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cache")
    os.makedirs(cache_dir, exist_ok=True)
    with open(os.path.join(cache_dir, "last_run.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)

    verified = [f for f in judged if f["verified"]]
    counts = {}
    for f in judged:
        counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
    print("\nNəticə:", counts)
    print(f"Təsdiqlənmiş boşluq: {len(verified)} / {len(judged)}")
    print(f"Ümumi təxmini məruz qalma (hadisə başına): {sum(f['estimated_loss_azn'] for f in verified)} AZN\n")
    for f in verified:
        print(f"[{f['severity'].upper()}] {f['rule_id']} ({f['attacker']}): {f['scenario'][:110]}...")
        print(f"   → Düzəliş: {f['fix']}\n")