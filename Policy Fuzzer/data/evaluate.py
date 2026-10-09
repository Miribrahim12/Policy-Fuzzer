"""Measure Policy Fuzzer against known hidden loopholes.

Usage (from the project root or from data/):
    python data/evaluate.py                       # run the pipeline on policy1.txt, then score
    python data/evaluate.py --result cache/last_run.json   # score a saved result, no pipeline run
    python data/evaluate.py --policy data/policy1.txt --truth data/ground_truth.json
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "backend"))

from llm import ask_json  # noqa: E402

SYSTEM = """You match audit findings to a list of KNOWN loopholes in a policy.
For each finding decide which known loophole (if any) it exploits.
Match only if the finding exploits the SAME underlying weakness in the policy wording.
A finding about a different weakness, or one the known list does not cover, gets null.
A finding matches at most one known loophole (pick the closest).
Return ONLY a JSON array, one item per finding: [{"i": 0, "gt": "G3"}, {"i": 1, "gt": null}]"""


def match(findings, truth, chunk=8):
    truth_txt = "\n".join(f'{t["id"]}: {t["title"]}. {t["description"]}' for t in truth)
    valid = {t["id"] for t in truth}
    result = {}
    for s in range(0, len(findings), chunk):
        part = findings[s:s + chunk]
        payload = [
            {"i": i, "policy_basis": f.get("policy_basis", ""), "scenario": f["scenario"], "fix": f.get("fix", "")}
            for i, f in enumerate(part)
        ]
        user = f"KNOWN LOOPHOLES:\n{truth_txt}\n\nFINDINGS:\n{json.dumps(payload, ensure_ascii=False)}"
        try:
            out = ask_json(SYSTEM, user, max_tokens=2000, temperature=0.0)
            for o in out:
                gt = o.get("gt")
                result[s + int(o["i"])] = gt if gt in valid else None
        except Exception as e:
            print(f"[match] error: {e}", file=sys.stderr)
    return [result.get(i) for i in range(len(findings))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=os.path.join(HERE, "policy1.txt"))
    ap.add_argument("--truth", default=os.path.join(HERE, "ground_truth.json"))
    ap.add_argument("--result", help="saved pipeline result JSON (skips running the pipeline)")
    args = ap.parse_args()

    truth = json.load(open(args.truth, encoding="utf-8"))

    if args.result:
        result = json.load(open(args.result, encoding="utf-8"))
    else:
        from pipeline import run
        text = open(args.policy, encoding="utf-8").read()
        print("Running pipeline (this takes a while)...")
        result = run(text)
        with open(os.path.join(HERE, "last_eval_result.json"), "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)

    findings = result.get("findings", [])
    if not findings:
        print("No verified findings: recall 0%.")
        return

    labels = match(findings, truth)
    found_ids = sorted({g for g in labels if g}, key=lambda x: int(x[1:]))
    missed = [t for t in truth if t["id"] not in found_ids]
    matched = [f for f, g in zip(findings, labels) if g]
    unmatched = [f for f, g in zip(findings, labels) if not g]

    recall = len(found_ids) / len(truth)
    precision = len(matched) / len(findings)

    print("\n=== RESULTS ===")
    print(f"Recall    : {len(found_ids)}/{len(truth)} hidden loopholes found = {recall:.0%}")
    print(f"Precision : {len(matched)}/{len(findings)} reported loopholes match a known one = {precision:.0%}")
    print("\nFOUND:")
    for t in truth:
        if t["id"] in found_ids:
            print(f'  [x] {t["id"]} (Art. {t["article"]}) {t["title"]}')
    print("\nMISSED:")
    for t in missed:
        print(f'  [ ] {t["id"]} (Art. {t["article"]}) {t["title"]}')
    print("\nNOT IN THE KNOWN LIST (review by hand; real extra loophole or false positive?):")
    for f in unmatched:
        print(f'  - {f["rule_id"]}: {f["scenario"][:140]}')
    print("\nNote: precision is measured against the known list only. Findings under"
          " 'NOT IN THE KNOWN LIST' may be genuine loopholes nobody planted, so true precision is >= this number.")

    report = {
        "recall": recall, "precision": precision,
        "found": found_ids, "missed": [t["id"] for t in missed],
        "unmatched_findings": [f["scenario"] for f in unmatched],
        "n_findings": len(findings), "n_truth": len(truth),
    }
    with open(os.path.join(HERE, "eval_report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print("\nSaved data/eval_report.json")


if __name__ == "__main__":
    main()
