"""Ask Infrared for the CPS Markdown of each final-certificate profile and save it next to the profile.

usage: gen_markdown.py
Writes ../profiles/<name>.generated.md. Precertificate profiles are skipped: the CP/CPS describes
them in one sentence relative to the final-certificate profile.
"""
import html, os, re
import infrared, matcher

for name, text in matcher.load_profiles().items():
    if not name.endswith("-final"):
        continue
    page = infrared.post("/profile/cps/", {"profile": text})
    md = re.search(r'<pre id="cps-markdown"[^>]*>(.*?)</pre>', page, re.S)
    if not md:
        raise SystemExit("no Markdown returned for %s" % name)
    path = os.path.join(matcher.PROFILE_DIR, name + ".generated.md")
    open(path, "w").write(html.unescape(md.group(1)).strip() + "\n")
    print("wrote", os.path.normpath(path))
