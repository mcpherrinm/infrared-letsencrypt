"""Minimal client for https://infrared.turbolightsolutions.com/profile/

usage:
  infrared.py validate PROFILE CERT.der [--html OUT]   -> prints findings
  infrared.py cps PROFILE OUT.html                      -> saves rendered CPS page
"""
import base64, html, http.cookiejar, re, sys, time, urllib.error, urllib.parse, urllib.request

BASE = "https://infrared.turbolightsolutions.com"
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
opener.addheaders = [("User-Agent", "le-infrared-test")]
_csrf = None


def csrf():
    global _csrf
    if _csrf is None:
        for attempt in range(4):
            try:
                page = opener.open(BASE + "/profile/", timeout=60).read().decode()
                break
            except urllib.error.HTTPError as e:
                if e.code not in (429, 502, 503) or attempt == 3:
                    raise
                time.sleep(2 * (attempt + 1))
        _csrf = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', page).group(1)
    return _csrf


def post(path, fields, retries=3):
    global _csrf
    for attempt in range(retries + 1):
        data = urllib.parse.urlencode({"csrfmiddlewaretoken": csrf(), **fields}).encode()
        req = urllib.request.Request(BASE + path, data=data, headers={"Referer": BASE + "/profile/"})
        try:
            return opener.open(req, timeout=120).read().decode()
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429, 502, 503) or attempt == retries:
                raise
            if e.code == 403:
                _csrf = None
            time.sleep(2 * (attempt + 1))


def pem(der):
    b = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def text(fragment):
    t = re.sub(r"<(script|style)\b.*?</\1>", "", fragment, flags=re.S)
    t = re.sub(r"<br\s*/?>|</(p|div|li|tr|h\d)>", "\n", t)
    t = re.sub(r"</t[dh]>", " | ", t)
    t = re.sub(r"<[^>]+>", "", t)
    t = html.unescape(t)
    return "\n".join(l.strip() for l in t.splitlines() if l.strip())


def validate(profile, der):
    return post("/profile/", {"profile": profile, "certificate": pem(der)})


if __name__ == "__main__":
    cmd = sys.argv[1]
    profile = open(sys.argv[2]).read()
    if cmd == "validate":
        page = validate(profile, open(sys.argv[3], "rb").read())
        if "--html" in sys.argv:
            open(sys.argv[sys.argv.index("--html") + 1], "w").write(page)
        body = page.split('id="profile-cert-form"', 1)[1]
        body = body.split("</form>", 1)[1]
        body = body.split("Eliminate profile drift", 1)[0]
        print(text(body))
    elif cmd == "cps":
        open(sys.argv[3], "w").write(post("/profile/cps/", {"profile": profile}))
