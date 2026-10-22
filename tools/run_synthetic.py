"""Check every cert in a directory against all profiles of its kind and write a plain-text report.

usage: run_synthetic.py CERTDIR OUT.txt
A defect is caught when no profile accepts the cert. The findings shown are from the profile the
cert's shape predicts.
"""
import os, sys
import matcher

certdir, out = sys.argv[1], sys.argv[2]
paths = [os.path.join(certdir, fn) for fn in sorted(os.listdir(certdir)) if fn.endswith(".der")]
lines = []
for r in matcher.match(paths):
    fn = os.path.basename(r["path"])
    if r["accepted_by"]:
        lines.append("ACCEPTED %s  by %s" % (fn, ", ".join(r["accepted_by"])))
        continue
    lines.append("CAUGHT   %s  (findings from %s)" % (fn, r["expected"]))
    for f in r["results"][r["expected"]]["findings"]:
        lines.append("    %s @ %s : %s" % (f["code"], f["location"], f["message"]))
open(out, "w").write("\n".join(lines) + "\n")
print("\n".join(l for l in lines if not l.startswith("    ")))
