import json
from attack import attack
from judge import judge

rules = [
    {"id": "R1", "text": "A single expense above 300 AZN and up to 2,000 AZN requires the written approval of the department manager.", "type": "approval"},
    {"id": "R2", "text": "A single expense above 2,000 AZN requires the written approval of the Finance Director.", "type": "approval"},
]
text = open("../data/policy1.txt", encoding="utf-8").read()
cands = attack(rules, text)
for f, j in zip(cands, judge(rules, cands)):
    print(j["verdict"], j["rule_id"], j["attacker"], "|", j["scenario"][:140], "|", j.get("reason", "")[:120])