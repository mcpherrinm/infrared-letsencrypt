"""Definitions for the ISRG / Let's Encrypt Infrared certificate profiles.

This file is the single source for every generated profile in ../profiles/. It is written in the
subset of Python that is also valid Starlark, so it must not use: imports, classes, f-strings,
while loops, recursion, try/except, sets, lambdas, the ** operator, chained comparisons, or
statements other than assignments and defs at the top level. tools/gen_profiles.py imports it and
writes the files; tools/check_starlark.sh evaluates it with a Starlark interpreter and compares
the output.

all_profiles() returns {file name: {"header": comment text, "profile": profile data}}.
"""

SCHEMA = "https://infrared.turbolightsolutions.com/infrared-profile-2026-10-02.schema.json"
CPS_VERSION = "CP/CPS v6.2 (Aug 12, 2026)"
PROFILES_PAGE = "https://letsencrypt.org/docs/profiles/"

# ---- Issuing CAs (CP/CPS 6.1.5: RSA-2048 or ECDSA P-384) ----
# Only the Gen Y Issuing CAs issue today; E5-E9 and R10-R14 are retired.
# dn: DER of the CA's subject Name. skid: the CA's subjectKeyIdentifier.
ISSUERS = {
    "rsa": [
        {"cn": "YR1", "dn": "3033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595231", "skid": "1f2f35be461482cd40b1ae792c5578faf7d468fb"},
        {"cn": "YR2", "dn": "3033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595232", "skid": "40152d2679ed32209edf9a721dd6321f810c810c"},
        {"cn": "YR3", "dn": "3033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303595233", "skid": "696529f933f809b642d5e1f3b5b59d1f5f7a227c"},
    ],
    "ecdsa": [
        {"cn": "YE1", "dn": "3033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594531", "skid": "bb20ca470bfed7e59cf98f092aa38c3745b1bcd8"},
        {"cn": "YE2", "dn": "3033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594532", "skid": "b959f28ecf22f086d33748ff761418ba82d85587"},
        {"cn": "YE3", "dn": "3033310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310c300a06035504031303594533", "skid": "f6a27ed65e236fdddd4546611e821575cdf1e68e"},
    ],
}

# Per subscriber key type: the issuing family, the signature algorithm that family's CAs use
# (CP/CPS 7.1.3.2 -> BR 7.1.3.2), and the allowed SubjectPublicKeyInfo algorithms (CP/CPS 6.1.5,
# 7.1.3.1 -> BR 7.1.3.1). Let's Encrypt issues RSA keys from YR CAs and ECDSA keys from YE CAs.
KEY_TYPES = {
    "rsa": {
        "label": "RSA",
        "ca_regex": "YR[1-3]",
        "ca_label": "yr[1-3]",
        "signature": {"name": "sha256WithRSAEncryption", "value": "300d06092a864886f70d01010b0500", "description": "RSASSA-PKCS1-v1_5 with SHA-256 (RSA-2048 Issuing CA keys)"},
        "spki": [
            {"name": "rsaEncryption", "value": "300d06092a864886f70d0101010500", "description": "RSA"},
        ],
    },
    "ecdsa": {
        "label": "ECDSA",
        "ca_regex": "YE[1-3]",
        "ca_label": "ye[1-3]",
        "signature": {"name": "ecdsaWithSha384", "value": "300a06082a8648ce3d040303", "description": "ECDSA with SHA-384 (P-384 Issuing CA keys)"},
        "spki": [
            {"name": "ecPublicKeyP256", "value": "301306072a8648ce3d020106082a8648ce3d030107", "description": "ECDSA on NIST P-256"},
            {"name": "ecPublicKeyP384", "value": "301006072a8648ce3d020106052b81040022", "description": "ECDSA on NIST P-384"},
            {"name": "ecPublicKeyP521", "value": "301006072a8648ce3d020106052b81040023", "description": "ECDSA on NIST P-521"},
        ],
    },
}

# ---- Let's Encrypt ACME profiles (https://letsencrypt.org/docs/profiles/) ----
# validity: cap in seconds. Infrared's validityPeriodSecs already counts inclusively per RFC 5280
# (notAfter - notBefore + 1s), so it is compared with valueLte.
# cn_variants: which subject forms the ACME profile produces ("cn" and/or "nocn").
# key_encipherment: set keyEncipherment for RSA keys. skid: include subjectKeyIdentifier.
ACME_PROFILES = [
    {
        "name": "classic",
        "validity": 90 * 86400,
        "cn_variants": ["cn", "nocn"],
        "san_types": ["dNSName"],
        "max_names": 100,
        "key_encipherment": True,
        "skid": True,
    },
    {
        "name": "tlsserver",
        "validity": 45 * 86400,
        "cn_variants": ["nocn"],
        "san_types": ["dNSName"],
        "max_names": 25,
        "key_encipherment": False,
        "skid": False,
    },
    {
        "name": "shortlived",
        "validity": 160 * 3600,
        "cn_variants": ["nocn"],
        "san_types": ["dNSName", "iPAddress"],
        "max_names": 25,
        "key_encipherment": False,
        "skid": False,
    },
]

KINDS = ["final", "precert"]


def variant_name(acme, cn, key, kind):
    parts = ["isrg", acme["name"]]
    if len(acme["cn_variants"]) > 1:
        parts.append(cn)
    parts.append(key)
    parts.append(kind)
    return "-".join(parts)


def variant_description(acme, cn, key, kind):
    if kind == "final":
        what = "Subscriber (Server) Certificate"
    else:
        what = "Precertificate"
    if cn == "cn":
        subject = "subject commonName present"
    else:
        subject = "subject commonName omitted"
    return "ISRG (Let's Encrypt) %s for the `%s` ACME profile: %s subscriber key, %s, issued by a Gen Y Issuing CA under the ISRG CP/CPS" % (
        what, acme["name"], KEY_TYPES[key]["label"], subject)


def header(acme, cn, key, kind):
    lines = [
        "GENERATED by tools/gen_profiles.py from tools/profile_defs.py. Do not edit by hand.",
        "",
        variant_description(acme, cn, key, kind) + ".",
        "",
        "Rendering of %s Section 7.1 \"%s\" (with the Section 6.1.5/6.1.6 key requirements and" % (
            CPS_VERSION, "Subscriber (Server) Certificate Profile" if kind == "final" else "Precertificate Profile"),
        "Section 7.1.3 algorithm identifiers), narrowed to what the `%s` ACME profile issues per" % acme["name"],
        PROFILES_PAGE + ". Where the CP/CPS defers to Baseline Requirements Section 7.1.2",
        "(e.g. extension criticality), the BR value is used.",
    ]
    return lines


def defs_for(key):
    kt = KEY_TYPES[key]
    defs = {}
    defs[kt["signature"]["name"]] = {"value": kt["signature"]["value"], "description": kt["signature"]["description"]}
    for alg in kt["spki"]:
        defs[alg["name"]] = {"value": alg["value"], "description": alg["description"]}
    defs["cabfDomainValidated"] = {"value": "2.23.140.1.2.1", "description": "Baseline Requirements Domain Validated Reserved Policy Identifier"}
    defs["idKpServerAuth"] = {"value": "1.3.6.1.5.5.7.3.1", "description": "id-kp-serverAuth"}
    for ca in ISSUERS[key]:
        defs["issuerDn" + ca["cn"]] = {"value": ca["dn"], "description": "C=US, O=Let's Encrypt, CN=" + ca["cn"]}
    for ca in ISSUERS[key]:
        defs["skid" + ca["cn"]] = {"value": ca["skid"], "description": ca["cn"]}
    defs["issuingCaLabel"] = kt["ca_label"]
    return defs


def subject_rule(cn):
    if cn == "nocn":
        return {
            "description": "Empty: the commonName is omitted and no other attributes are included (Section 7.1.4).",
            "size": {"max": 0},
        }
    return {
        "description": "Contains only a commonName, which is one of the values from the Subject Alternative Name extension (Section 7.1.4).",
        "size": {"min": 1, "max": 1},
        # A dNSName of at most 64 characters; matching it against the SAN isn't expressible here.
        "rdns": [{"commonName": {"valueMatch": "^[A-Za-z0-9*._-]{1,64}$"}}],
    }


def key_usage_rule(acme, key):
    bits = [{"bit": "digitalSignature"}]
    if acme["key_encipherment"] and key == "rsa":
        bits.append({"bit": "keyEncipherment"})
    return {"keyUsage": {"clause": "7.1", "critical": True, "bits": bits}}


def san_rule(acme, cn):
    types = acme["san_types"]
    if cn == "cn":
        crit_text = "Not critical, because the subject commonName is present."
    else:
        crit_text = "Critical, because the subject commonName is omitted."
    return {"subjectAltName": {
        "clause": "7.1",
        "critical": cn == "nocn",
        "description": crit_text,
        "names": {
            "pattern": [{"type": t} for t in types],
            "size": {"min": 1, "max": acme["max_names"]},
        },
    }}


def ct_rule(kind):
    if kind == "final":
        return {"sctList": {
            "clause": "7.1",
            "critical": False,
            "description": "Contains at least two SCTs from logs run by different operators.",
        }}
    return {"precertificatePoison": {
        "clause": "7.1",
        "critical": True,
        "description": "CT poison extension (OID 1.3.6.1.4.1.11129.2.4.3).",
    }}


def extensions(acme, cn, key, kind):
    cas = ISSUERS[key]
    entries = [
        {"authorityInformationAccess": {
            "clause": "7.1",
            "critical": False,
            "description": "Contains the HTTP URI of the Issuing CA's Certificate.",
            "accessDescriptions": [{
                "method": "caIssuers",
                "accessLocation": {"type": "uniformResourceIdentifier", "valueMatch": "^http://%issuingCaLabel%\\.i\\.lencr\\.org/$"},
            }],
        }},
        {"authorityKeyIdentifier": {
            "clause": "7.1",
            "critical": False,
            "description": "Contains a keyIdentifier byte-for-byte identical to the subjectKeyIdentifier of the Issuing CA.",
            "keyIdentifier": {"valueHexOneOf": [{"eq": "%skid" + ca["cn"] + "%"} for ca in cas]},
        }},
        {"basicConstraints": {"clause": "7.1", "critical": True, "ca": False}},
        {"certificatePolicies": {
            "clause": "7.1",
            "critical": False,
            "policies": [{"policyIdentifier": "%cabfDomainValidated%"}],
        }},
        {"crlDistributionPoints": {
            "clause": "7.1",
            "critical": False,
            "description": "Contains the HTTP URI of a CRL issued by the Issuing CA whose scope includes this certificate.",
            "distributionPoints": [{"distributionPoint": {"fullName": {"exact": [
                {"type": "uniformResourceIdentifier", "valueMatch": "^http://%issuingCaLabel%\\.c\\.lencr\\.org/[0-9]+\\.crl$"},
            ]}}}],
        }},
        {"extendedKeyUsage": {
            "clause": "7.1",
            "critical": False,
            "purposes": [{"oid": "%idKpServerAuth%"}],
        }},
        key_usage_rule(acme, key),
        ct_rule(kind),
        san_rule(acme, cn),
    ]
    if acme["skid"]:
        entries.append({"subjectKeyIdentifier": {
            "clause": "7.1",
            "critical": False,
            "description": "Contains a truncated hash of the subjectPublicKey, per Section 2(1) of RFC 7093.",
            # A 160-bit (20-byte) truncated hash.
            "valueHexMatch": "^[0-9a-f]{40}$",
        }})
    # The CP/CPS doesn't mandate an extension order.
    return {"ordered": False, "entries": entries}


def subject_public_key(key):
    kt = KEY_TYPES[key]
    rule = {"algorithm": {"clause": "7.1.3.1", "algorithms": ["%" + alg["name"] + "%" for alg in kt["spki"]]}}
    if key == "rsa":
        rule["rsa"] = {
            "modulusLength": {"clause": "6.1.5", "valueOneOf": [{"eq": 2048}, {"eq": 3072}, {"eq": 4096}]},
            "exponent": {"clause": "6.1.6", "valueEq": 65537},
        }
    return rule


def profile(acme, cn, key, kind):
    kt = KEY_TYPES[key]
    cas = ISSUERS[key]
    return {
        "$schema": SCHEMA,
        "type": "certificate",
        "name": variant_name(acme, cn, key, kind),
        "version": "0.2.0",
        "description": variant_description(acme, cn, key, kind),
        "org": "isrg",
        "spec": "cp-cps",
        "$defs": defs_for(key),
        "content": {
            "version": {"valueEq": "v3", "clause": "7.1.1"},
            "serialNumber": {
                "clause": "7.1",
                "description": "More than 100 bits of output from a CSPRNG, optionally with additional non-random bits.",
                # Randomness itself can't be checked here.
                "valueGt": 0,
            },
            "signatureAlgorithm": {"clause": "7.1.3.2", "algorithms": ["%" + kt["signature"]["name"] + "%"]},
            "signatureValue": {"description": "A signature appropriate to the signatureAlgorithm field."},
            "validity": {
                "clause": "7.1",
                "validityPeriodSecs": {"valueLte": acme["validity"]},
            },
            "subjectPublicKey": subject_public_key(key),
            "issuer": {
                "description": "Byte-for-byte identical to the subject field of the Issuing CA.",
                "tlvHexOneOf": [{"eq": "%issuerDn" + ca["cn"] + "%"} for ca in cas],
                "rdns": [
                    {"countryName": {"valueEq": "US"}},
                    {"organizationName": {"valueEq": "Let's Encrypt"}},
                    {"commonName": {"valueMatch": "^" + kt["ca_regex"] + "$"}},
                ],
            },
            "subject": subject_rule(cn),
            "extensions": extensions(acme, cn, key, kind),
        },
    }


def variants():
    out = []
    for acme in ACME_PROFILES:
        for cn in acme["cn_variants"]:
            for key in ["rsa", "ecdsa"]:
                for kind in KINDS:
                    out.append({"acme": acme, "cn": cn, "key": key, "kind": kind})
    return out


def all_profiles():
    result = {}
    for v in variants():
        name = variant_name(v["acme"], v["cn"], v["key"], v["kind"])
        result[name + ".json5"] = {
            "header": header(v["acme"], v["cn"], v["key"], v["kind"]),
            "profile": profile(v["acme"], v["cn"], v["key"], v["kind"]),
        }
    return result
