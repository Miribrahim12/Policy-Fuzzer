import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

from judge import judge
from pipeline import build_stats, dedupe

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
SRC = os.path.join(DATA, "last_eval_result.json")
DST = os.path.join(DATA, "last_eval_result_rejudged_dedup.json")

with open(SRC, encoding="utf-8") as fh:
    data = json.load(fh)

if not isinstance(data, dict) or not data.get("rules"):
    print("XƏTA: last_eval_result.json-da 'rules' yoxdur, rejudge mümkün deyil.")
    sys.exit(1)

rules = data["rules"]
old = data.get("findings", [])
print(f"Yenidən hökmləndirilir: {len(old)} tapıntı")

judged = judge(rules, old)
counts = {}
for f in judged:
    counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
print("Yeni hökmlər:", counts)

valid = [dict(f, duplicates=0, attackers=[f["attacker"]]) for f in judged if f["verified"]]
unique = dedupe(valid)
stats = build_stats((data.get("stats") or {}).get("candidates", 0), counts, len(valid), unique)

with open(DST, "w", encoding="utf-8") as fh:
    json.dump({"rules": rules, "findings": unique, "stats": stats}, fh, ensure_ascii=False, indent=2)
print(f"Dedupe-dan sonra: {len(unique)} unikal boşluq")
print(f"Yazıldı: {DST}")