"""Build synthetic certs cloned from a real YR-series Let's Encrypt cert, each with one deliberate defect.

Signed with a throwaway RSA-2048 key using sha256WithRSAEncryption (Infrared doesn't verify the
issuer's signature, only the profile). Writes OUTDIR/<name>.der.
usage: mutants.py TEMPLATE.der OUTDIR
"""
import datetime, ipaddress, os, sys
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.name import _ASN1Type

tpl = x509.load_der_x509_certificate(open(sys.argv[1], "rb").read())
outdir = sys.argv[2]
os.makedirs(outdir, exist_ok=True)
ca_key = rsa.generate_private_key(65537, 2048)
leaf_rsa = rsa.generate_private_key(65537, 2048)
leaf_ec = ec.generate_private_key(ec.SECP256R1())


def ext(oid):
    return tpl.extensions.get_extension_for_oid(oid)


def P(oid, v):
    return x509.NameAttribute(oid, v, _type=_ASN1Type.PrintableString)


def build(name, *, key=leaf_rsa, issuer=None, subject=None, days=None, secs=None, serial=None,
          replace=None, drop=(), add=(), hash_alg=hashes.SHA256()):
    replace = replace or {}
    nb = tpl.not_valid_before_utc
    na = nb + (datetime.timedelta(seconds=secs) if secs is not None else
               datetime.timedelta(days=days) - datetime.timedelta(seconds=1) if days else
               tpl.not_valid_after_utc - nb)
    b = (x509.CertificateBuilder()
         .issuer_name(issuer if issuer is not None else tpl.issuer)
         .subject_name(subject if subject is not None else tpl.subject)
         .serial_number(serial or tpl.serial_number)
         .not_valid_before(nb).not_valid_after(na)
         .public_key(key.public_key()))
    for e in tpl.extensions:
        if e.oid in drop:
            continue
        if e.oid in replace:
            v, crit = replace[e.oid]
            if v is None:
                continue
            b = b.add_extension(v, crit)
            continue
        v = e.value
        if e.oid == ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS:
            v = x509.UnrecognizedExtension(e.oid, v.public_bytes())
        b = b.add_extension(v, e.critical)
    for v, crit in add:
        b = b.add_extension(v, crit)
    cert = b.sign(ca_key, hash_alg)
    open(os.path.join(outdir, name + ".der"), "wb").write(cert.public_bytes(serialization.Encoding.DER))


from cryptography.hazmat.primitives import serialization

KU = ExtensionOID.KEY_USAGE
def ku(enc=False, ds=True):
    return x509.KeyUsage(ds, False, enc, False, False, False, False, False, False)

san = ext(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
aia = ext(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
cdp = ext(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
ca_url = aia[0].access_location.value
crl_url = cdp[0].full_name[0].value

build("00-baseline")
build("01-validity-91-days", days=91)
build("02-validity-90-days-plus-1s", secs=90 * 86400)
build("03-eku-clientauth", replace={ExtensionOID.EXTENDED_KEY_USAGE: (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)})
build("04-aia-ocsp-added", replace={ExtensionOID.AUTHORITY_INFORMATION_ACCESS: (x509.AuthorityInformationAccess([
    x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier("http://ocsp.example.org")),
    aia[0]]), False)})
build("05-policy-ov", replace={ExtensionOID.CERTIFICATE_POLICIES: (x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.2"), None)]), False)})
build("06-policy-cps-qualifier", replace={ExtensionOID.CERTIFICATE_POLICIES: (x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), ["http://cps.letsencrypt.org"])]), False)})
build("07-aki-unknown", replace={ExtensionOID.AUTHORITY_KEY_IDENTIFIER: (x509.AuthorityKeyIdentifier(b"\x11" * 20, None, None), False)})
build("08-issuer-retired-r3", issuer=x509.Name([P(NameOID.COUNTRY_NAME, "US"), P(NameOID.ORGANIZATION_NAME, "Let's Encrypt"), P(NameOID.COMMON_NAME, "R3")]))
build("09-issuer-utf8-encoding", issuer=x509.Name([P(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Let's Encrypt", _type=_ASN1Type.UTF8String),
    x509.NameAttribute(NameOID.COMMON_NAME, tpl.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, _type=_ASN1Type.UTF8String)]))
build("10-subject-has-org", subject=x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"), x509.NameAttribute(NameOID.COMMON_NAME, san.value[0].value)]))
build("11-rsa-1024", key=rsa.generate_private_key(65537, 1024))
build("12-rsa-exponent-3", key=rsa.generate_private_key(3, 2048))
build("13-ec-p224", key=ec.generate_private_key(ec.SECP224R1()))
build("14-ec-secp256k1", key=ec.generate_private_key(ec.SECP256K1()))
build("15-crl-https", replace={ExtensionOID.CRL_DISTRIBUTION_POINTS: (x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url.replace("http:", "https:"))], None, None, None)]), False)})
build("16-crl-two-urls", replace={ExtensionOID.CRL_DISTRIBUTION_POINTS: (x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url), x509.UniformResourceIdentifier("ldap://crl.example.org")], None, None, None)]), False)})
build("17-ca-issuers-wrong-host", replace={ExtensionOID.AUTHORITY_INFORMATION_ACCESS: (x509.AuthorityInformationAccess([
    x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("http://x1.i.lencr.org/"))]), False)})
build("18-basic-constraints-ca", replace={ExtensionOID.BASIC_CONSTRAINTS: (x509.BasicConstraints(True, None), True)})
build("19-ku-missing-digitalsignature", replace={KU: (x509.KeyUsage(False, False, True, False, False, False, False, False, False), True)})
build("20-ku-noncritical", replace={KU: (ku(), False)})
build("21-san-101-names", replace={ExtensionOID.SUBJECT_ALTERNATIVE_NAME: (x509.SubjectAlternativeName([x509.DNSName(f"h{i}.example.org") for i in range(101)]), san.critical)})
build("22-san-email", replace={ExtensionOID.SUBJECT_ALTERNATIVE_NAME: (x509.SubjectAlternativeName([san.value[0], x509.RFC822Name("a@example.org")]), san.critical)})
# cryptography refuses >159-bit serials: build("23-serial-21-octets", serial=(1 << 167) + 12345)
build("24-must-staple-extension", add=[(x509.TLSFeature([x509.TLSFeatureType.status_request]), False)])
build("25-sha224-signature", hash_alg=hashes.SHA224())
build("26-no-sct-no-poison", drop=(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,))
build("27-both-sct-and-poison", add=[(x509.PrecertPoison(), True)])
build("28-ec-key-with-keyencipherment", key=leaf_ec, replace={KU: (ku(enc=True), True)})
build("29-no-cn-san-noncritical", subject=x509.Name([]), replace={ExtensionOID.SUBJECT_ALTERNATIVE_NAME: (san.value, False)})
build("30-cn-not-in-san", subject=x509.Name([P(NameOID.COMMON_NAME, "not-in-san.example.org")]))
build("31-crl-from-other-issuer", replace={ExtensionOID.CRL_DISTRIBUTION_POINTS: (x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier("http://e7.c.lencr.org/3.crl")], None, None, None)]), False)})
build("32-skid-sha256-full", replace={ExtensionOID.SUBJECT_KEY_IDENTIFIER: (x509.SubjectKeyIdentifier(b"\x22" * 32), False)})
# Rules that only the per-ACME-profile split can express (the template is a classic RSA cert with a CN).
build("33-classic-ip-san", replace={ExtensionOID.SUBJECT_ALTERNATIVE_NAME: (x509.SubjectAlternativeName([san.value[0], x509.IPAddress(ipaddress.ip_address("192.0.2.1"))]), san.critical)})
build("34-classic-rsa-no-keyencipherment", replace={KU: (ku(), True)})
build("35-cn-with-critical-san", replace={ExtensionOID.SUBJECT_ALTERNATIVE_NAME: (san.value, True)})
build("36-classic-no-skid", drop=(ExtensionOID.SUBJECT_KEY_IDENTIFIER,))
print("ok", ca_url, crl_url, tpl.subject.rfc4514_string(), san.critical)
