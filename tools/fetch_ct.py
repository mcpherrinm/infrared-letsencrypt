"""Fetch recent entries from Let's Encrypt static-ct-api logs and save LE-issued certs.

usage: fetch_ct.py OUTDIR NTILES MONITOR_URL [MONITOR_URL...]
"""
import gzip, json, os, struct, sys, urllib.request, concurrent.futures as cf
from cryptography import x509
from cryptography.x509.oid import NameOID


def get(url):
    req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip", "User-Agent": "le-infrared-test"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
        if r.headers.get("Content-Encoding") == "gzip" or data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        return data


def tile_path(n):
    s = f"{n:d}"
    s = "0" * ((3 - len(s) % 3) % 3) + s
    parts = [s[i:i + 3] for i in range(0, len(s), 3)]
    return "/".join(["x" + p for p in parts[:-1]] + [parts[-1]])


def parse_tile(data):
    i = 0
    out = []
    while i < len(data):
        ts, etype = struct.unpack(">QH", data[i:i + 10]); i += 10
        if etype == 0:
            ln = int.from_bytes(data[i:i + 3], "big"); i += 3
            cert = data[i:i + ln]; i += ln
            ext = int.from_bytes(data[i:i + 2], "big"); i += 2 + ext
        else:
            i += 32
            ln = int.from_bytes(data[i:i + 3], "big"); i += 3 + ln  # tbs
            ext = int.from_bytes(data[i:i + 2], "big"); i += 2 + ext
            ln = int.from_bytes(data[i:i + 3], "big"); i += 3
            cert = data[i:i + ln]; i += ln
        chain = int.from_bytes(data[i:i + 2], "big"); i += 2 + chain
        out.append((ts, etype, cert))
    return out


def main():
    outdir, ntiles, mons = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
    os.makedirs(outdir, exist_ok=True)
    jobs = []
    for mon in mons:
        mon = mon.rstrip("/")
        size = int(get(mon + "/checkpoint").decode().split("\n")[1])
        last_full = size // 256 - 1
        # spread tiles across the most recent ~2M entries to diversify
        step = int(os.environ.get("STEP", max(1, 8000 // ntiles)))
        for k in range(ntiles):
            jobs.append((mon, last_full - k * step))
    stats = {"entries": 0, "le": 0}
    with cf.ThreadPoolExecutor(8) as ex:
        for (mon, n), data in zip(jobs, ex.map(lambda j: get(f"{j[0]}/tile/data/{tile_path(j[1])}"), jobs)):
            for idx, (ts, etype, der) in enumerate(parse_tile(data)):
                stats["entries"] += 1
                try:
                    c = x509.load_der_x509_certificate(der)
                    org = c.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                except Exception:
                    continue
                if not org or org[0].value != "Let's Encrypt":
                    continue
                stats["le"] += 1
                kind = "final" if etype == 0 else "precert"
                name = f"{mon.split('//')[1].split('.')[1]}-{n * 256 + idx}-{kind}.der"
                with open(os.path.join(outdir, name), "wb") as f:
                    f.write(der)
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
