"""Write every profile defined in profile_defs.py to ../profiles/.

usage: gen_profiles.py [--check | --json]
  --check  exit 1 if any file in ../profiles/ is missing, stale or unexpected; write nothing
  --json   print all_profiles() as compact JSON (used by check_starlark.sh)
"""
import json, os, sys
import profile_defs

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "profiles")


def render(entry):
    head = "".join(("// " + l).rstrip() + "\n" for l in entry["header"])
    return head + json.dumps(entry["profile"], indent=2, ensure_ascii=False) + "\n"


profiles = profile_defs.all_profiles()
if "--json" in sys.argv:
    print(json.dumps(profiles, sort_keys=True, separators=(",", ":")))
    sys.exit(0)

wanted = {name: render(entry) for name, entry in profiles.items()}
existing = {n for n in os.listdir(OUT) if n.endswith(".json5")} if os.path.isdir(OUT) else set()
if "--check" in sys.argv:
    bad = sorted(n for n in wanted if n not in existing or open(os.path.join(OUT, n)).read() != wanted[n])
    bad += sorted(existing - set(wanted))
    for n in bad:
        print("out of date:", n)
    sys.exit(1 if bad else 0)

os.makedirs(OUT, exist_ok=True)
for n in sorted(existing - set(wanted)):
    os.remove(os.path.join(OUT, n))
    print("removed", n)
for n, text in sorted(wanted.items()):
    open(os.path.join(OUT, n), "w").write(text)
print("wrote %d profiles to %s" % (len(wanted), os.path.normpath(OUT)))
