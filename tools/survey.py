"""Summarize the shape of a directory of DER certificates."""
import collections, os, sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec

d = sys.argv[1]
C = collections.defaultdict(collections.Counter)
examples = {}
for fn in sorted(os.listdir(d)):
    der = open(os.path.join(d, fn), "rb").read()
    c = x509.load_der_x509_certificate(der)
    kind = fn.rsplit("-", 1)[1][:-4]
    C["kind"][kind] += 1
    C["issuer"][c.issuer.rfc4514_string()] += 1
    C["issuer_der"][c.issuer.public_bytes().hex()] += 1
    C["sigalg"][c.signature_algorithm_oid.dotted_string] += 1
    C["version"][c.version.name] += 1
    C["serial_bytes"][(c.serial_number.bit_length() + 8) // 8] += 1
    v = (c.not_valid_after_utc - c.not_valid_before_utc).total_seconds()
    C["validity_secs"][int(v)] += 1
    pk = c.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        C["key"][f"rsa{pk.key_size} e={pk.public_numbers().e}"] += 1
    else:
        C["key"][f"ec {pk.curve.name}"] += 1
    C["subject"][",".join(a.oid._name for a in c.subject)] += 1
    for a in c.subject:
        C["subject_cn_tag"][a._type.name] += 1
    order = []
    for e in c.extensions:
        name = e.oid._name if e.oid._name != "Unknown OID" else e.oid.dotted_string
        order.append(name + ("!" if e.critical else ""))
        if e.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            names = e.value
            C["san_types"][",".join(sorted({type(n).__name__ for n in names}))] += 1
            C["san_count_bucket"][min(len(list(names)), 100) // 10 * 10] += 1
            C["san_crit_vs_cn"][(e.critical, bool(c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)))] += 1
            if any(isinstance(n, x509.IPAddress) for n in names):
                examples.setdefault("ip", fn)
        elif e.oid == ExtensionOID.KEY_USAGE:
            ku = e.value
            bits = [b for b in ["digital_signature", "key_encipherment", "content_commitment", "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign"] if getattr(ku, b)]
            C["ku"][(",".join(bits), "rsa" if isinstance(pk, rsa.RSAPublicKey) else "ec")] += 1
        elif e.oid == ExtensionOID.EXTENDED_KEY_USAGE:
            C["eku"][",".join(o.dotted_string for o in e.value)] += 1
        elif e.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            C["aia"][";".join(f"{a.access_method._name}={a.access_location.value}" for a in e.value)] += 1
        elif e.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            for dp in e.value:
                u = dp.full_name[0].value
                C["crldp_host"][u.split("/")[2]] += 1
                C["crldp_shape"][(len(e.value), len(dp.full_name), dp.reasons, dp.crl_issuer, u.split("/")[2].split(".", 1)[1])] += 1
        elif e.oid == ExtensionOID.CERTIFICATE_POLICIES:
            C["cp"][";".join(p.policy_identifier.dotted_string + (f"[{p.policy_qualifiers}]" if p.policy_qualifiers else "") for p in e.value)] += 1
        elif e.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            C["aki"][(c.issuer.rfc4514_string(), e.value.key_identifier.hex(), e.value.authority_cert_issuer is None)] += 1
        elif e.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            C["skid_len"][len(e.value.digest)] += 1
        elif e.oid == ExtensionOID.BASIC_CONSTRAINTS:
            C["bc"][(e.critical, e.value.ca, e.value.path_length)] += 1
    C["ext_order"][(kind, " ".join(order))] += 1
    if not c.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        examples.setdefault("nocn-" + kind, fn)
    examples.setdefault(f"{kind}-{int(v)}-{type(pk).__name__[:3]}", fn)

for k, v in C.items():
    print(f"== {k} ({len(v)} distinct)")
    for item, n in v.most_common(25):
        print(f"   {n:6d}  {item}")
print("== examples")
for k, v in sorted(examples.items()):
    print("  ", k, v)
