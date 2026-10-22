"""Check every cert in the given directories against all profiles of its kind, and summarize.

usage: match.py OUT.json CERTDIR [CERTDIR...]
A cert passes if exactly one profile accepts it and that is the profile its shape predicts.
OUT.json keeps the findings only for each cert's expected profile.
"""
import collections, json, os, sys
import matcher

out = sys.argv[1]
paths = [os.path.join(d, fn) for d in sys.argv[2:] for fn in sorted(os.listdir(d)) if fn.endswith(".der")]
results = matcher.match(paths)
summary = collections.Counter()
for r in results:
    if r["accepted_by"] == [r["expected"]]:
        outcome = "accepted by expected profile only"
    elif not r["accepted_by"]:
        outcome = "accepted by none"
    elif len(r["accepted_by"]) > 1:
        outcome = "accepted by several"
    else:
        outcome = "accepted by a different profile"
    r["outcome"] = outcome
    summary[outcome] += 1
    r["findings"] = r["results"].get(r["expected"], {}).get("findings", [])
    del r["results"]
    if outcome != "accepted by expected profile only":
        print(outcome, r["path"], r["expected"], r["accepted_by"])
        for f in r["findings"]:
            print("   ", f["code"], "@", f["location"], ":", f["message"])
json.dump(results, open(out, "w"), indent=1)
for k, v in summary.most_common():
    print("%4d %s" % (v, k))
by_profile = collections.Counter(r["accepted_by"][0] for r in results if len(r["accepted_by"]) == 1)
for k, v in sorted(by_profile.items()):
    print("%4d %s" % (v, k))
