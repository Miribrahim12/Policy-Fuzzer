import json
import sys

from attack import COMMON, PERSONAS
from extract import SAMPLE
from llm import _call

text = open(sys.argv[1], encoding="utf-8").read() if len(sys.argv) > 1 else SAMPLE
mt = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
rules = [{"id": f"R{i}", "text": "x" * 80, "type": "condition"} for i in range(1, 11)]
user = f"RULES TO ATTACK:\n{json.dumps(rules)}\n\nFULL POLICY TEXT:\n{text}"
system = PERSONAS["fraudster"]
print("təxmini giriş simvolu:", len(system) + len(user), "| max_tokens:", mt)
try:
    out = _call(system, user, mt, 0.8)
    print("OK, cavab uzunluğu:", len(out))
except Exception as e:
    print("XƏTA:")
    print(str(e)[:900])