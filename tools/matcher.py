"""Check certs against every generated profile in ../profiles/.

A cert should be accepted by exactly one profile of its kind (final or precert). expected_profile()
names that profile from the cert's shape, and is used to pick which findings to show when a cert is
accepted by none.
"""
import os, re
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
import infrared

PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "profiles")


def load_profiles():
    out = {}
    for fn in sorted(os.listdir(PROFILE_DIR)):
        if fn.endswith(".json5"):
            out[fn[:-len(".json5")]] = open(os.path.join(PROFILE_DIR, fn)).read()
    return out


def kind_of(filename):
    return "precert" if filename.endswith("-precert.der") else "final"


def expected_profile(der, kind):
    c = x509.load_der_x509_certificate(der)
    secs = (c.not_valid_after_utc - c.not_valid_before_utc).total_seconds()
    key = "rsa" if isinstance(c.public_key(), rsa.RSAPublicKey) else "ecdsa"
    if secs < 160 * 3600:
        acme = "shortlived"
    elif secs < 45 * 86400:
        acme = "tlsserver"
    else:
        acme = "classic-cn" if c.subject else "classic-nocn"
    return "isrg-%s-%s-%s" % (acme, key, kind)


def check(profile, der):
    """Returns (status, findings); status is conformant, findings or compile-error."""
    page = infrared.validate(profile, der)
    body = page.split("</form>", 1)[1].split("Certificate Details", 1)[0]
    rows = []
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", body, re.S):
        cells = [" ".join(infrared.text(td).split()) for td in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
        if len(cells) >= 4:
            rows.append({"code": cells[1].split("cp-cps:")[-1],
                         "location": cells[2].removeprefix("Certificate.tbsCertificate."),
                         "message": cells[3]})
    if "No findings" in body:
        return "conformant", rows
    if "couldn't be compiled" in body:
        return "compile-error", [{"code": "compile", "location": "", "message": infrared.text(body)[:500]}]
    return "findings", rows


def match(paths, workers=4):
    """Checks each cert against every profile of its kind. Returns one dict per path, in order."""
    profiles = load_profiles()
    jobs = []
    for path in paths:
        kind = kind_of(path)
        der = open(path, "rb").read()
        for name, text in profiles.items():
            if name.endswith("-" + kind):
                jobs.append((path, name, text, der))
    infrared.csrf()  # fetch the token once, so the workers share one session
    with ThreadPoolExecutor(workers) as pool:
        verdicts = list(pool.map(lambda j: check(j[2], j[3]), jobs))
    by_path = {}
    for (path, name, _, der), (status, rows) in zip(jobs, verdicts):
        r = by_path.setdefault(path, {"path": path, "expected": expected_profile(der, kind_of(path)),
                                      "accepted_by": [], "results": {}})
        r["results"][name] = {"status": status, "findings": rows}
        if status == "conformant":
            r["accepted_by"].append(name)
    return [by_path[p] for p in paths]
