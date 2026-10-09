import sys

P = "judge.py"
s = open(P, encoding="utf-8").read()

if "fictitious clients" in s:
    print("Artıq tətbiq olunub.")
    sys.exit(0)

old1 = "claiming a trip that did not happen). That is fraud, not a policy flaw."
new1 = ("claiming a trip that did not happen). Also forgery: the scenario needs the employee to record, "
        "label or report something differently from what actually happened (e.g. recording a business-class "
        "ticket as economy, listing fictitious clients, claiming nights not stayed). "
        "That is fraud, not a policy flaw.")
old2 = "or it does not defeat the rule's purpose, or it is immaterial."
new2 = (old2 + " Also not_a_loophole: it relies on an older or hypothetical version of the policy, "
        "or on a future policy change.")

if s.count(old1) != 1 or s.count(old2) != 1:
    print(f"XƏTA: uyğun mətn tapılmadı (old1={s.count(old1)}, old2={s.count(old2)}). judge.py-ı əl ilə redaktə et.")
    sys.exit(1)

s = s.replace(old1, new1).replace(old2, new2)
open(P, "w", encoding="utf-8").write(s)
print("judge.py yeniləndi.")