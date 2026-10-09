import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from pipeline import build_stats, dedupe

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
SRC = os.path.join(DATA, "last_eval_result.json")
DST = os.path.join(DATA, "last_eval_result_dedup.json")

with open(SRC, encoding="utf-8") as fh:
    data = json.load(fh)

if isinstance(data, list):
    rules, findings, old_stats = [], data, {}
else:
    rules = data.get("rules", [])
    findings = data.get("findings", [])
    old_stats = data.get("stats") or {}

findings = [dict(f, duplicates=0, attackers=[f["attacker"]])
            for f in findings if f.get("verified", True)]
print(f"Dedupe-dan əvvəl: {len(findings)} tapıntı")

unique = dedupe(findings)
stats = build_stats(old_stats.get("candidates", 0), old_stats.get("verdicts", {}),
                    len(findings), unique)

with open(DST, "w", encoding="utf-8") as fh:
    json.dump({"rules": rules, "findings": unique, "stats": stats},
              fh, ensure_ascii=False, indent=2)

print(f"Dedupe-dan sonra: {len(unique)} unikal boşluq")
print(f"Yazıldı: {DST}")