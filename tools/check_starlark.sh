#!/bin/sh
# Evaluate profile_defs.py with a Starlark interpreter and check it yields the same profiles as CPython.
# usage: check_starlark.sh [STARLARK_BINARY]
# Install the interpreter with: go install go.starlark.net/cmd/starlark@latest
set -eu
cd "$(dirname "$0")"
STARLARK="${1:-starlark}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
{ cat profile_defs.py; echo 'print(json.encode(all_profiles()))'; } > "$tmp/defs.star"
"$STARLARK" "$tmp/defs.star" 2> "$tmp/star.json" > /dev/null
python3 gen_profiles.py --json > "$tmp/py.json"
python3 -c 'import json, sys; sys.exit(json.load(open(sys.argv[1])) != json.load(open(sys.argv[2])))' "$tmp/star.json" "$tmp/py.json"
echo "profile_defs.py evaluates identically under Starlark and CPython"
