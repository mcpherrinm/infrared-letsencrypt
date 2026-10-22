# Let's Encrypt subscriber profiles for Infrared

This is a trial of [Infrared](https://infrared.turbolightsolutions.com/profile/) as a single source of truth for the
Subscriber (Server) Certificate Profile and the Precertificate Profile in the
[ISRG CP/CPS](https://github.com/letsencrypt/cp-cps/blob/main/CP-CPS.md) (v6.2, Aug 12 2026). There is one profile per
[Let's Encrypt ACME profile](https://letsencrypt.org/docs/profiles/) and variant, so rules that the CP/CPS states as
conditions become plain per-profile rules.

| Path | What it is |
| --- | --- |
| `profiles/*.json5` | The 16 generated Infrared profiles (schema `infrared-profile-2026-10-02`). Don't edit them by hand. |
| `profiles/*-final.generated.md` | What Infrared's "Write Markdown" produces for each final-certificate profile. |
| `tools/profile_defs.py` | The single source for all profiles, written in the Python subset that is also valid Starlark. |
| `tools/gen_profiles.py` | Writes `profiles/*.json5` from `profile_defs.py` (`--check` verifies they are up to date). |
| `tools/check_starlark.sh` | Evaluates `profile_defs.py` with a Starlark interpreter and checks the output matches CPython's. |
| `results/ct-sample-results.json` | Which profiles accept each of 253 real certs sampled from Sycamore/Willow 2026h2. |
| `results/synthetic-defect-results.txt` | The same for a clean baseline, 35 synthetic certs with one deliberate defect each, and 2 real expired clientAuth certs. |
| `certs/ct-sample/` | The 253 real certs (DER). Names are `<log>-<index>-<precert\|final>.der`. |
| `certs/synthetic/` | The defect certs (DER). They are signed by a throwaway key, so they don't chain to anything. |
| `tools/` (other) | The static-ct-api tile fetcher, a survey of cert shapes, the Infrared client, the matcher, the defect generator, and the Markdown generator. |

## The profiles

Each profile is named `isrg-<acme profile>[-cn|-nocn]-<rsa|ecdsa>-<final|precert>`:

| Base profile | Validity cap | Subject | SAN | keyUsage | SKID |
| --- | --- | --- | --- | --- | --- |
| `classic-cn-rsa` | 90 days | CN only, ≤64 chars | not critical; 1–100 dNSName | digitalSignature, keyEncipherment | required |
| `classic-cn-ecdsa` | 90 days | CN only, ≤64 chars | not critical; 1–100 dNSName | digitalSignature | required |
| `classic-nocn-rsa` | 90 days | empty | critical; 1–100 dNSName | digitalSignature, keyEncipherment | required |
| `classic-nocn-ecdsa` | 90 days | empty | critical; 1–100 dNSName | digitalSignature | required |
| `tlsserver-rsa` | 45 days | empty | critical; 1–25 dNSName | digitalSignature | absent |
| `tlsserver-ecdsa` | 45 days | empty | critical; 1–25 dNSName | digitalSignature | absent |
| `shortlived-rsa` | 160 hours | empty | critical; 1–25 dNSName/iPAddress | digitalSignature | absent |
| `shortlived-ecdsa` | 160 hours | empty | critical; 1–25 dNSName/iPAddress | digitalSignature | absent |

- **Key type**: `rsa` profiles allow RSA 2048/3072/4096 keys (e=65537), are issued by YR1–YR3, and are signed with
  sha256WithRSAEncryption. `ecdsa` profiles allow P-256/P-384/P-521 keys, are issued by YE1–YE3, and are signed with
  ecdsa-with-SHA384. All issuance is from the Gen Y CAs; E5–E9 and R10–R14 are retired and not accepted.
- **`-final` vs `-precert`**: final certs require the SCT list; precerts require the critical CT poison instead.
- **Shared by all**: issuer DN matched byte-for-byte; AKI equal to one of the family's SKIDs; exactly one caIssuers URI
  `http://<ca>.i.lencr.org/` and one CRL URI `http://<ca>.c.lencr.org/<n>.crl` (required by a root program); DV
  policy OID only; serverAuth EKU only; basicConstraints critical with cA false. Extension order isn't enforced.
- **Criticality**: wherever the CP/CPS table is silent, BR 7.1.2.7 values are used, as CP/CPS §7.1 says it derives
  from those profiles.
- **Validity**: capped at the ACME profile's period with `valueLte`. Infrared's `validityPeriodSecs` already counts
  inclusively per RFC 5280, so a 90-day cert reports exactly 7,776,000 s. (The earlier single profile used `valueLt`
  on the 100-day cap, which wrongly rejected a cert of exactly 100 days.)

### Editing

Change `tools/profile_defs.py`, then:

```sh
cd tools
python3 gen_profiles.py          # rewrite profiles/*.json5
./check_starlark.sh              # needs: go install go.starlark.net/cmd/starlark@latest
python3 gen_markdown.py          # refresh profiles/*-final.generated.md (calls the Infrared site)
```

`profile_defs.py` uses no imports, classes, f-strings, while loops, recursion, try/except, sets, lambdas, `**`, chained
comparisons, or top-level statements other than assignments and `def`s. It builds plain data; JSON serialization and
file writing are in `gen_profiles.py`.

## Results

Each cert is checked against all 8 profiles of its kind (final or precert). A real cert should be accepted by
exactly one, the one its shape predicts; a defect is caught when no profile accepts it.

### Real certificates (253 sampled from LE's own CT logs)

| Outcome | Count |
| --- | --- |
| Accepted by exactly the profile its shape predicts | 165 |
| Accepted by both `shortlived` and `tlsserver` (shortlived certs with only dNSName SANs) | 30 |
| Accepted by none: issued by a retired CA (E7, E8, R12, R13) | 57 |
| Accepted by none: a March 2026 YR1 precert shaped like `tlsserver` but valid for 90 days | 1 |

Every one of the 16 profiles accepts at least 4 real certs. The 57 retired-issuer certs include the expired
`clientAuth` precert that was the one real finding under the earlier single profile.

**Overlap**: with validity as a cap only, a 160-hour cert with only DNS names meets every `tlsserver` rule, since the two
ACME profiles differ only in validity and IP support. Adding a lower bound to `tlsserver` (e.g. more than 160
hours) would make the profiles mutually exclusive.

### Synthetic defects (cloned from a real YR1 classic cert with a CN, and re-signed)

The re-signed baseline is accepted by `classic-cn-rsa-final` only.

**Caught (34 synthetic, plus the 2 real clientAuth certs):**
- validity of 91 days, and of 90 days + 1 s
- clientAuth EKU (both synthetic and real)
- OCSP added to AIA
- OV policy OID; CPS qualifier on the policy
- unknown AKI; issuer CN=R3; issuer DN re-encoded as UTF8String
- O= in the subject
- RSA-1024; e=3; P-224 and secp256k1 keys
- https CRL URL; two CRL URLs; CRL URL from E7 (another issuer family); wrong caIssuers host
- cA=TRUE; KU missing digitalSignature; KU not critical
- 101 SANs; rfc822Name SAN
- extra extension (must-staple)
- sha224WithRSA signature; 32-byte SKID
- final cert with neither an SCT list nor a CT poison; with both
- **newly caught by the split**: EC key with keyEncipherment; no CN with a non-critical SAN; CN with a critical
  SAN; IP SAN in a classic cert; classic RSA cert without keyEncipherment; classic cert without SKID

**Still not catchable** (cross-field rules):

| CP/CPS rule | Why it can't be expressed |
| --- | --- |
| CN is one of the SAN values (defect 30 is accepted) | No cross-field reference |
| CRL DP / AIA host matches the actual issuer | Only "one of the family's 3 CAs": a yr2 URL on a YR1 cert would pass |
| At least two SCTs from different operators | SCTs are opaque bytes |

A 21-octet serial wasn't tested, because the `cryptography` library refuses to build one.

## Infrared issues

Resolved:
- ECDSA signatures were reported as undisclosed `ECDSASigValue.{r,s}` fields. The author fixed this.
- "dNSName or iPAddress" SANs: `names.pattern` accepts a list of patterns. The engine always allowed this; the
  schema didn't advertise it.

Open:
1. The cross-field gaps in the table above.
2. No `$includes` on the website, so shared rules need a generator (here, `profile_defs.py`).
3. **Error output is noisy.**
   - A `*OneOf` failure prints one line per alternative.
   - RSA modulus-length failures show hex (`valueEq "0800"`) rather than bit counts.
   - Name blocks don't accept `clause`, unlike most other blocks, so issuer/subject rows get no Reference in the
     generated Markdown.

## Reproducing

```sh
cd tools
python3 fetch_ct.py ../certs 20 https://mon.sycamore.ct.letsencrypt.org/2026h2 https://mon.willow.ct.letsencrypt.org/2026h2
python3 survey.py ../certs
python3 match.py ../results/out.json ../certs
python3 mutants.py TEMPLATE.der ../certs/synthetic   # TEMPLATE: a real YR1 classic cert with a CN
python3 run_synthetic.py ../certs/synthetic ../results/synthetic.txt
```

Set `STEP=180000` on `fetch_ct.py` to spread tiles across the whole log instead of only the latest entries.
