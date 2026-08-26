---
title: "An EAT Profile for Composite Platform Attestation"
abbrev: "Composite Platform Attestation"
category: std
docname: draft-sun-rats-composite-eat-latest
submissiontype: IETF
consensus: true
v: 3
area: "Security"
workgroup: "Remote ATtestation ProcedureS"
keyword:
 - attestation
 - EAT
 - CoRIM
 - SPDM
 - composite device
 - platform attestation
venue:
  group: "Remote ATtestation ProcedureS"
  type: "Working Group"
  mail: "rats@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/rats/"
  github: "helloxiling/draft-sun-rats-composite-eat"

author:
 -
    ins: X. Sun
    name: Xiling Sun
    org: Microsoft
    email: xiling.sun@microsoft.com
 -
    ins: R. Krishnamurthy
    name: Raghu Krishnamurthy
    org: NVIDIA
    email: raghupathyk@nvidia.com
 -
    ins: R. Golizadeh Mojarad
    name: Roksana Golizadeh Mojarad
    org: Microsoft
    email: roksanag@microsoft.com

normative:
  RFC8610:  # CDDL
  RFC8949:  # CBOR
  RFC8392:  # CWT
  RFC9052:  # COSE structures
  RFC9053:  # COSE algorithms
  RFC5280:  # PKIX certificate validation
  RFC9360:  # COSE X.509 header parameters
  RFC9711:  # EAT
  RFC9782:  # EAT media types
  RFC9334:  # RATS Architecture
  DSP0274:
    target: https://www.dmtf.org/dsp/DSP0274
    title: "Security Protocol and Data Model (SPDM) Specification"
    author:
      - org: DMTF
    date: 2024
    seriesinfo:
      DSP0274: Version 1.3.2

informative:
  RFC9999:  # RATS Conceptual Message Wrapper
  I-D.ietf-rats-corim:
  I-D.poirier-rats-eat-da:
  TCG-DICE-CE:
    target: https://trustedcomputinggroup.org/
    title: "DICE Attestation Architecture (Concise Evidence)"
    author:
      - org: Trusted Computing Group
    date: false

--- abstract

This document defines an Entity Attestation Token (EAT) profile for
composite platform attestation. A Lead Attester, such as a platform Root
of Trust, produces a single signed composite EAT that carries its own
measurements and cryptographic digests committing to detached, native
evidence collected from peripheral sub-attesters. The full sub-attester
evidence -- Security Protocol and Data Model (SPDM) signed measurements,
device-emitted EATs, or
SPDM-carried TCG DICE Concise Evidence -- is conveyed verbatim as
detached Claims-Sets in a Detached EAT Bundle. This yields a single,
freshness-bound, platform-scoped attestation artifact that a Verifier
can appraise against platform-composition endorsements, even when the
evidence is collected and conveyed by an untrusted mediator.

--- middle

# Introduction

## Problem Statement

Platform attestation today is disaggregated. Where per-device evidence
is retrievable (for example, over a Redfish-based interface), attesting a
whole server takes N separate transactions returning N independently
signed responses, and the Verifier must reconstruct platform topology
from those separate per-device results. There is no signed,
platform-level artifact that binds a single Verifier nonce, the platform
Root of Trust (RoT) state, and the set of device evidence reported for
the platform.

Three gaps follow:

1. No aggregate. There is no single signed platform-scoped artifact; the
   Verifier reassembles the platform from independent per-device results.

2. No uniform claim. Devices variously expose SPDM signed measurements,
   emit their own signed EAT, or carry TCG DICE Concise Evidence inside
   SPDM measurements. No common platform structure carries these forms
   together without rewriting device evidence.

3. Heavier RoT firmware footprint. Attesting the platform RoT under the
   same per-device model would force a full SPDM responder path onto the
   RoT solely to attest itself.

## Approach

A Lead Attester ({{Section 3.3 of RFC9334}} composite device pattern)
produces one signed composite EAT. The composite EAT carries the Lead
Attester's own measurements and, for each peripheral sub-attester, a
detached-submodule digest that commits to the sub-attester's evidence.
The evidence itself is preserved in its native encoding and conveyed
separately as a detached Claims-Set within a Detached EAT Bundle (CBOR
tag 602, {{RFC9711}}). The signed digests bind the detached evidence;
the native bytes preserve each device's own end-to-end signature.

## Relationship to Other RATS Work

{{I-D.poirier-rats-eat-da}} defines an EAT profile for per-device
attestation evidence in confidential-computing device assignment, and
notes that such a device token is "typically enclosed in a wider
platform specific attestation token." This document defines that
enclosing, signed, self-attesting composite envelope for the
platform/operator use case. A device token of that form MAY be carried
as one detached sub-attester payload ({{native-evidence}}); the two
profiles address different consumers and are complementary.

## Scope

This document specifies the composite EAT evidence format: the signed
composite token, the detached sub-attester evidence carriage, and the
binding between them. Appraisal of the composite against a platform
composition endorsement (for example, a platform CoRIM profile) is
summarized informatively in {{verification}} and specified separately.
Tenant-side attestation and TDISP composition are outside the scope of
this document. Physical slot locality and bus-level anti-relay guarantees are
also outside scope; this profile supports identity-based anti-substitution.
Trust-anchor enrollment, endorsement authoring, and transport/collection APIs
are also outside scope.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

Data structures are defined using the Concise Data Definition Language
(CDDL) {{RFC8610}}.

This document uses the terms Attester, Verifier, Relying Party, Endorser,
Reference Value Provider, Lead Attester, Sub-Attester, Composite Device,
Target Environment, and Attesting Environment as defined in {{RFC9334}}.

Additional terms:

Detached Claims-Set:
: The native sub-attester evidence for one Target Environment, encoded as
  a CBOR Claims-Set and conveyed in the detached slot of the Detached EAT
  Bundle, committed to by a digest in the signed composite EAT.

Target Environment Identifier:
: A stable, operator-owned topology label (rendered as an `env.*` string)
  used as the map key for a sub-attester in both the signed `submods`
  claim and the detached Claims-Set map.

Untrusted Collector:
: The entity that discovers sub-attesters, collects evidence, and
  assembles the bundle. It is not trusted for content: it MAY drop,
  reorder, or mislabel evidence, but MUST NOT be able to forge it.

# Architecture and Trust Model

## Composite Device Realization

This profile realizes the {{Section 3.3 of RFC9334}} composite device
pattern. The Lead Attester signs the composite EAT and contributes its
own Attesting-Environment identity and measurements. Peripheral devices
are Sub-Attesters whose evidence appears only as detached-submodule
digests in the signed token, with the full evidence detached.

The Lead Attester does not appear as a submodule; its claims are
top-level claims of the composite EAT.

This profile does not replace native Sub-Attester verification. A Verifier
MUST validate each Sub-Attester signature or other native evidence protection
in addition to validating the composite EAT signature.

## Untrusted Collector and Conveyance

The entity that collects sub-attester evidence and assembles the bundle
is untrusted for content. Its labels and completeness are not proven by
the composite signature; they are appraisal inputs. The design goal is
that a misbehaving collector can cause detectable failures (missing or
mismatched digests, failed device signatures) but cannot forge evidence
or the composite signature. See {{security}}.

## Role Mapping

| Component | RFC 9334 role |
| --------- | ------------- |
| Lead Attester (e.g. platform RoT) | Lead Attester |
| Peripheral device | Sub-Attester |
| Collector / conveyance | Evidence collection / conveyance |
| Endorser / RVP | Endorser / Reference Value Provider |
| Verifier | Verifier |
| Consumer of the Attestation Result | Relying Party |
{: title="RATS role mapping"}

# The Signed Composite EAT

## Profile Conformance {#profile-conformance}

This section states the {{Section 6 of RFC9711}} profile items for this
profile.

| Profile item | This profile |
| ------------ | ------------ |
| Profile identifier (`eat_profile`, claim 265) | `https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/` |
| Serialization | CBOR {{RFC8949}} with deterministic encoding and definite-length items |
| Top-level message | Detached EAT Bundle with tag 602 {{RFC9711}} |
| Top-level media type | `application/eat-bun+cbor` {{RFC9782}} |
| Main token | CWT tag 61 containing COSE_Sign1 tag 18 |
| Token protection | COSE_Sign1 {{RFC9052}} using ES384 (algorithm -35) {{RFC9053}} |
| Detached digest | SHA-384 (algorithm -43), 48-byte output {{RFC9053}} |
| Key identification | Protected SHA-384 `x5t` (label 34) and unprotected leaf-first `x5chain` (label 33) {{RFC9360}} |
| Freshness | One 32-byte `eat_nonce`, unique for each request |
| Main token content type | `application/eat+cwt` {{RFC9782}} |
{: title="Profile conformance"}

Conforming producers MUST emit every choice in the table above. Conforming
Verifiers MUST support those choices. This is a full EAT profile in the sense
of {{Section 6.2 of RFC9711}}.

## Bundle Structure {#bundle}

The authoritative artifact is a Detached EAT Bundle (CBOR tag 602,
{{RFC9711}}). This profile does not redefine the tag-602 construct; it
constrains its two slots: slot 1 is the signed composite EAT
(`main-token`); slot 2 is the detached Claims-Set map keyed by Target
Environment Identifier and defined in {{detached-evidence}}.
When conveyed with a media type, the bundle MUST use
`application/eat-bun+cbor` {{RFC9782}}.

~~~ cddl
composite-bundle = #6.602([
  main-token: bstr .cbor composite-eat,         ; slot 1, see 4.3/4.4
  detached-claims-sets: {                  ; slot 2, see Section 5
    + env-id => bstr .cbor detached-claims-set
  }
])

composite-eat = #6.61(#6.18([      ; COSE_Sign1-tagged CWT
  protected:   bstr .cbor protected-headers,
  unprotected: unprotected-headers,
  payload:     bstr .cbor composite-eat-claims,
  signature:   bstr
]))

protected-headers = {
  1:  -35,                     ; alg: ES384
  3:  "application/eat+cwt",  ; content_type
  34: certificate-thumbprint   ; x5t: SHA-384 of leaf certificate
}

certificate-thumbprint = [ -43, bstr .size 48 ]

unprotected-headers = {
  33: cose-x509-chain          ; x5chain: leaf certificate first
}

cose-x509-chain = bstr / [ 2* bstr ]
~~~

Every certificate in `cose-x509-chain` is a DER-encoded certificate. When the
chain contains more than one certificate, it MUST be ordered starting with the
Lead Attester end-entity certificate, as specified by {{RFC9360}}. The
protected `x5t` MUST use SHA-384 (algorithm -43) and MUST equal the SHA-384
digest of the complete DER encoding of that end-entity certificate. This
integrity-protects the end-entity certificate while allowing `x5chain` to be
carried in the unprotected header bucket, as permitted by {{RFC9360}}.

A Verifier MUST reject the token if the protected `x5t` does not match the
first certificate in `x5chain`. It MUST treat every carried certificate as
untrusted input and validate a path to a trust anchor configured independently
of the bundle, including applicable certificate usage, validity, and
revocation checks {{RFC5280}}.

## Top-Level Claims {#top-claims}

~~~ cddl
composite-eat-claims = {
  10:  bstr .size 32,     ; eat_nonce      (MANDATORY) Verifier nonce
  265: general-uri,      ; eat_profile    (MANDATORY)
  256: bstr .size (7..33), ; ueid         (MANDATORY) Lead id
  273: measurements-type, ; measurements  (MANDATORY) see 4.4
  266: submods-type,      ; submods       (MANDATORY) see 5.1
  ? TBD_PLATFORM_CORIM_ID => general-uri, ; OPTIONAL locator hint
}
~~~

The `eat_nonce` claim contains exactly one nonce. The Verifier MUST generate a
new nonce for every request, and the same nonce MUST be used to obtain each
nonce-capable Sub-Attester evidence item included in the resulting bundle.

The `TBD_PLATFORM_CORIM_ID` claim is a Verifier lookup/audit hint only
and is not appraisal authority; see {{iana}}.

## Lead Attester Self-Measurements {#self-meas}

The Lead Attester's platform-local evidence (RoT and platform firmware)
is carried in the top-level `measurements` claim (273), not in `submods`.

~~~ cddl
measurements-type = [ + lead-attester-measurement ]

lead-attester-measurement = [
  content-format: uint .le 65535,  ; payload CoAP Content-Format
  value: bstr                      ; payload bytes per content-format
]
~~~

This constrains the `measurements` claim format defined by {{RFC9711}};
it does not define a map-based replacement for that claim. The Lead
Attester MUST use a registered CoAP Content-Format for each `value`.

# Detached Sub-Attester Evidence {#detached-evidence}

## Detached-Submodule-Digest Binding {#digest-binding}

Every Sub-Attester is represented in the signed token as a
Detached-Submodule-Digest ({{RFC9711}}). The full evidence is the
detached Claims-Set in slot 2 of {{bundle}}, keyed by the same Target
Environment Identifier.

~~~ cddl
submods-type = { + env-id => detached-submodule-digest }

detached-submodule-digest = [
  hash-alg: -43,          ; SHA-384 in the COSE Algorithms registry
  digest:   bstr .size 48 ; over encoded detached Claims-Set bytes
]

env-id = tstr
~~~

Binding invariant: for every Target Environment Identifier E,
`submods[E]` in the signed token MUST equal the digest, computed per
{{digest-rules}}, of `detached-claims-sets[E]` in the bundle.
The key set of `submods` MUST be identical to the key set of
`detached-claims-sets`. A Verifier MUST reject a bundle containing a missing
or unreferenced detached Claims-Set.

Using detached digests for every Sub-Attester keeps the signed composite token
and the Lead Attester input bounded by Sub-Attester count rather than by native
evidence size. It also allows additional native evidence formats without
changing the `submods` shape.

## Deterministic Encoding and Digest Rules {#digest-rules}

Each detached Claims-Set MUST be encoded with deterministic CBOR
({{Section 4.2 of RFC8949}}). The detached-submodule digest MUST be
computed over the encoded Claims-Set bytes directly, not over the
byte-string wrapper used in the bundle and not over any textual
encoding. This rule is the anti-forgery anchor: a modified or fabricated
detached Claims-Set fails either the signed digest comparison or the
device evidence signature check.

SHA-384 (COSE algorithm -43) MUST be used for every detached-submodule
digest. This digest algorithm is independent of any measurement hash
algorithm negotiated by a native evidence protocol such as SPDM.

## Native Evidence Carriage {#native-evidence}

Sub-attester evidence is preserved in its native encoding as the value of one
profile-defined CWT claim. Using one integer claim key satisfies the CBOR claim
key requirements of {{RFC9711}} while allowing the profile to carry several
native evidence formats.

~~~ cddl
detached-claims-set = {
  TBD_NATIVE_EVIDENCE => native-evidence
}

native-evidence = spdm-evidence / device-eat-evidence
~~~

The Collector constructs the enclosing Claims-Set and evidence-type array. It
MUST NOT alter, translate, or re-author the native evidence bytes placed in
that array.

### SPDM Signed Measurements

~~~ cddl
spdm-evidence = [
  evidence-type: 1,
  signed-measurements: bstr,  ; native SignedMeasurements bytes
  cert-chain: bstr,           ; reassembled SPDM certificate chain
  ? vca: bstr                 ; required for SPDM 1.0/1.1
]
~~~

`signed-measurements` is the binary Redfish/SPDM SignedMeasurements value. For
SPDM 1.2 and later it includes the negotiated-version, capabilities, and
algorithms (VCA) transcript; for SPDM 1.0 and 1.1 it contains only the signed
`GET_MEASUREMENTS` exchange. `cert-chain` is the raw reassembled SPDM
certificate-chain object, not a PEM encoding or management-interface
projection. `vca` is the observed VCA transcript and MUST be present for SPDM
1.0 and 1.1; it MUST be absent for SPDM 1.2 and later. See {{DSP0274}}.

### Device-Emitted EAT

~~~ cddl
device-eat-evidence = [
  evidence-type: 2,
  token-format: tstr,   ; media type, e.g. "application/eat+cwt"
  device-token: bstr
]
~~~

`device-token` MUST contain the complete token as emitted by the device, and
`token-format` MUST identify its media type. The token MUST cryptographically
bind the Verifier nonce. A device token of the form defined in
{{I-D.poirier-rats-eat-da}} MAY be carried here.

### SPDM-Carried TCG DICE Concise Evidence

Signed measurements that carry TCG DICE Concise Evidence {{TCG-DICE-CE}}
use the `spdm-evidence` schema above; the measurement blocks
are preserved verbatim.

The Collector does not need to distinguish ordinary SPDM measurements from
SPDM measurements carrying TCG DICE Concise Evidence. The Verifier interprets
the signed measurement blocks according to the applicable evidence profile.

### Relationship to Conceptual Message Wrappers

This profile does not permit Conceptual Message Wrapper (CMW) typed values
inside `TBD_NATIVE_EVIDENCE`; allowing an alternate inner representation would
make the digest input ambiguous. A conveying protocol MAY carry the complete
`composite-bundle` as a CMW typed value {{RFC9999}}. Such an
outer wrapper is not part of any detached Claims-Set digest input.

## Target Environment Identifier {#env-id}

The `submods` key and detached Claims-Set map key is a stable,
operator-owned Target Environment Identifier, distinct from SPDM slot
IDs, MCTP EIDs, device UUIDs, and CoRIM IDs. It:

1. is lowercase ASCII;
2. is dot-separated with first component `env`;
3. names the expected environment, not the device instance;
4. is at most 64 bytes.

Examples: `env.nic.0`, `env.gpu.0`, `env.pcie.4`.

# Verification (Informative) {#verification}

A Verifier is expected to perform the following checks before producing an
attestation result:

1. Decode the bundle, confirm tag 602, and enforce the encoding and algorithm
  choices in {{profile-conformance}}.
2. Match protected `x5t` to the end-entity certificate in `x5chain`, validate
  the Lead Attester certificate path, and validate the COSE_Sign1 signature.
3. Match `eat_nonce` to the challenge, match `eat_profile` to this profile, and
  validate the Lead Attester `ueid` and measurements.
4. Require identical `submods` and detached Claims-Set key sets, then recompute
  every digest per {{digest-rules}}.
5. Parse each `TBD_NATIVE_EVIDENCE` value, validate its native signature and
  certificate or token chain, and match its nonce to the challenge.
6. Match the identity proven by each native evidence item to the expected
  identity for its Target Environment Identifier.

Completeness and anti-substitution are appraisal outcomes, not properties
of the composite signature alone. They are determined by comparing the
signed `submods` set and proven device identities against a platform
composition endorsement (for example, a platform CoRIM profile;
see {{I-D.ietf-rats-corim}}), which is specified separately.
Native Sub-Attester measurements are appraised against trusted device
reference values, such as vendor CoRIMs, selected by Verifier policy. This
profile does not define endorsement selection or reference-value appraisal.

# Security Considerations {#security}

The security considerations of {{RFC8392}}, {{RFC9052}}, {{RFC9360}},
{{RFC9711}}, and {{RFC9334}} apply.

## Untrusted Collector Threat Model

The Collector may drop, reorder, or mislabel evidence. A dropped device
yields no valid submodule digest; exact key-set checking detects a detached
Claims-Set omitted from the bundle, while appraisal against a platform
composition endorsement detects an expected environment omitted from both
maps. Reordering has no semantic effect because both collections are maps and
their deterministic encodings are checked by digest. A mislabeled environment
is detected when the identity proven by native evidence does not match the
expected identity for that Target Environment. If appraisal policy has no
trusted identity-to-environment binding, this profile alone cannot detect such
substitution.

The Collector cannot forge the composite signature or a Sub-Attester's native
signature. It can, however, choose the label and digest records submitted to
the Lead Attester. Consequently, the composite signature proves integrity and
freshness of the included set; it does not prove that collection was complete
or that a label was assigned correctly.

The profile binds a proven Sub-Attester identity to a logical Target
Environment Identifier. It does not prove physical connector locality or
prevent bus-level relay. Deployments requiring those properties need an
additional platform-specific transport or hardware binding.

## Provenance Preservation

Because sub-attester evidence is carried verbatim and pinned by a signed
digest, device signatures remain end-to-end verifiable through an
untrusted Collector. A Verifier MUST validate both layers: accepting the
composite signature without validating native evidence would incorrectly treat
Collector-authored bytes as device-authored evidence.

The top-level nonce prevents replay of the composite EAT. Each native evidence
item MUST independently prove binding to the same nonce; otherwise a Collector
could combine current platform evidence with stale device evidence. A Verifier
MUST reject a native evidence item whose nonce is absent, unverifiable, or does
not match the challenge.

The fixed ES384 and SHA-384 choices prevent algorithm substitution at the
composite layer. For SPDM 1.0 and 1.1, the separately carried VCA transcript is
not covered by the responder's measurement signature. Deployments requiring
cryptographic binding of negotiated SPDM parameters MUST require SPDM 1.2 or
later in appraisal policy.

## Aggregator Self-Attestation and Key Handling

The Lead Attester signs with a protected attestation key and contributes
its own measurements. The signing key and the source of `ueid` and top-level
measurements MUST be protected from the Collector. The `ueid` MUST be
provisioned according to {{RFC9711}} and remain stable for the Lead Attester.

Compromise of the Lead Attester signing key permits forgery of the composite
envelope, its nonce, Lead Attester measurements, labels, and device-evidence
digests. It does not permit forgery of uncompromised Sub-Attester signatures,
but it defeats the platform-scoped binding supplied by this profile. Verifiers
therefore MUST validate the Lead Attester certificate path, revocation state,
and applicable authorization policy rather than trusting a chain merely
because it is carried in `x5chain`. They MUST also match the protected `x5t`
to the end-entity certificate before accepting the Lead Attester signature.

If `x5chain` were accepted without the protected `x5t` check, an attacker could
substitute another certificate for the same public key and cause an identity
misbinding when the issuing CA did not require proof of possession. The
protected `x5t` prevents this attack by signing the exact end-entity
certificate identity {{RFC9360}}.

## Resource Exhaustion

Detached evidence, certificate chains, and the number of submodules are
attacker-influenced inputs. Implementations SHOULD enforce deployment-specific
limits on bundle size, Claims-Set size, certificate-chain length, and submodule
count. Verifiers SHOULD validate structure and signed digests before performing
expensive native-evidence appraisal, without treating a valid digest as a
substitute for native signature validation.

# Privacy Considerations

A stable Lead Attester `ueid` and end-entity certificate enable correlation of
attestations from the same platform. Native device certificates and
device-emitted tokens can similarly identify and correlate individual
Sub-Attesters. Target Environment Identifiers expose platform topology, and
measurements can reveal firmware versions or configuration.

Deployments SHOULD restrict bundle access to authorized Verifiers and use a
confidentiality-protected conveying protocol when these identifiers or
measurements are sensitive. A Verifier SHOULD disclose only the attestation
result needed by a Relying Party rather than forwarding the complete bundle.
Verifier nonces SHOULD be unpredictable random values and MUST NOT encode user,
account, workload, or other identifying information. Where stable platform
identification is unnecessary, deployments should use a context-specific
identity mechanism in a separate profile; replacing `ueid` ad hoc would not
conform to this profile.

# IANA Considerations {#iana}

## Native Evidence CWT Claim

IANA is requested to register the following in the "CBOR Web Token (CWT)
Claims" registry:

* Claim Name: Native Evidence
* Claim Description: Native evidence carried in a detached Claims-Set
* JWT Claim Name: N/A
* Claim Key: TBD (`TBD_NATIVE_EVIDENCE`)
* Claim Value Type: array
* Change Controller: IETF
* Reference: {{native-evidence}} of this document

## Platform CoRIM Locator CWT Claim

IANA is requested to register the following in the "CBOR Web Token (CWT)
Claims" registry:

* Claim Name: Platform CoRIM Locator
* Claim Description: Locator hint for a platform CoRIM
* JWT Claim Name: N/A
* Claim Key: TBD (`TBD_PLATFORM_CORIM_ID`)
* Claim Value Type: URI
* Change Controller: IETF
* Reference: {{top-claims}} of this document

## EAT Profile Identifier

This document defines the provisional `eat_profile` value
`https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/`. This value
identifies the complete profile defined by this Internet-Draft. It is expected
to be replaced by an RFC-based identifier if this document is published as an
RFC; implementations of an Internet-Draft version therefore MUST treat this
value as provisional.

--- back

# Worked Example {#appendix-example}

This non-normative example uses temporary claim keys 60000 and 60001 from
{{appendix-cddl}}. The Verifier nonce is the 32-byte sequence 0x00 through
0x1f. The Lead Attester and device token use separate P-384 signing keys and
self-signed example certificates. These certificates are test inputs, not
trust anchors for deployment. For compactness, the SPDM byte strings are
illustrative carriage values rather than a complete SPDM transcript and
certificate chain.

The following diagnostic notation elides long certificates, signatures, and
nested token bytes. The complete encoded bundle follows it.

~~~ cbor-diag
602([
  <<61(18([
    <<{
      1: -35,
      3: "application/eat+cwt",
      34: [-43,
        h'6be9f10e1e9388b0f70028b060dc215a0dc4f1b2d60b407689465be40d6e1a28e31e3d7186968eac00ea97db833d715c']
    }>>,
    {33: h'<Lead Attester certificate>'},
    <<{
      10: h'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      256: h'0111111111111111111111111111111111',
      265: "https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/",
      266: {
        "env.accel.0": [-43,
          h'a24620821bdc8c9aec86dae14bbce0a627c13fe41cefe58eb20cd748eb56154391368d509d001f70e1c6cfe2815c388c'],
        "env.nic.0": [-43,
          h'3032f9a41a6156dc45e054276a775bebade2a795c2412b91319326c6a299af6c2ceba175fc8fa4c51eb7721939760cf1']
      },
      273: [[60, h'a1015830aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']],
      60001: "tag:example.com,2026:platform-corim:v1"
    }>>,
    h'<Lead Attester ES384 signature>'
  ]))>>,
  {
    "env.accel.0": <<{
      60000: [2, "application/eat+cwt", h'<device CWT>']
    }>>,
    "env.nic.0": <<{
      60000: [1, h'12010000aabbccdd', h'30820100deadbeef']
    }>>
  }
])
~~~

The SHA-384 digest of the encoded `env.nic.0` Claims-Set is
`3032f9a41a6156dc45e054276a775bebade2a795c2412b91319326c6a299af6c2ceba175fc8fa4c51eb7721939760cf1`.
The SHA-384 digest of the encoded `env.accel.0` Claims-Set is
`a24620821bdc8c9aec86dae14bbce0a627c13fe41cefe58eb20cd748eb56154391368d509d001f70e1c6cfe2815c388c`.
Both values appear under claim 266 in the signed main token.

The complete 1682-byte bundle is below. A backslash indicates that one
hexadecimal string continues on the next display line; the backslash and
following indentation are not part of the encoded value.

~~~ hex
d9025a825903b2d83dd2845850a301382203736170706c69636174696f6e2f65\
  61742b637774182282382a58306be9f10e1e9388b0f70028b060dc215a0dc4f1\
  b2d60b407689465be40d6e1a28e31e3d7186968eac00ea97db833d715ca11821\
  590189308201853082010ca003020102020101300a06082a8648ce3d04030330\
  1d311b301906035504030c12436f6d706f7369746520454154204c656164301e\
  170d3236303130313030303030305a170d3335303130313030303030305a301d\
  311b301906035504030c12436f6d706f7369746520454154204c656164307630\
  1006072a8648ce3d020106052b8104002203620004aa87ca22be8b05378eb1c7\
  1ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e\
  3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da31\
  13b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fa320301e300c0603551d13\
  0101ff04023000300e0603551d0f0101ff040403020780300a06082a8648ce3d\
  0403030367003064023019cb7d09c07d9219ba0ba82b672fe390f7d7213c7c53\
  7555c2da46d446337ec9aa4a5f3c2428e83fb96c221ec56cfc6602302ab0be75\
  23d7b0d26e7578d3a5edd42aeb413721cb28448d38c57be38fcfb4e4486d28a9\
  4769251239cf21bf9e990429590168a60a5820000102030405060708090a0b0c\
  0d0e0f101112131415161718191a1b1c1d1e1f19010051011111111111111111\
  1111111111111111190109783e68747470733a2f2f64617461747261636b6572\
  2e696574662e6f72672f646f632f64726166742d73756e2d726174732d636f6d\
  706f736974652d6561742f19010aa269656e762e6e69632e3082382a58303032\
  f9a41a6156dc45e054276a775bebade2a795c2412b91319326c6a299af6c2ceb\
  a175fc8fa4c51eb7721939760cf16b656e762e616363656c2e3082382a5830a2\
  4620821bdc8c9aec86dae14bbce0a627c13fe41cefe58eb20cd748eb56154391\
  368d509d001f70e1c6cfe2815c388c1901118182183c5834a1015830aaaaaaaa\
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
  aaaaaaaaaaaaaaaaaaaaaaaa19ea6178267461673a6578616d706c652e636f6d\
  2c323032363a706c6174666f726d2d636f72696d3a763158609ba7bac0c1a7ae\
  bf32dd0ba61b9a805b083078f9a2ef213f29ca65251b377e866e1d86831c127c\
  3d833f204f46f11c440477e9acfb3aa33dfc198d4ecfd617fc76560533ec2052\
  db23ff6bb269ca38070e77858cb5178f9824009d6d1b29f2bea269656e762e6e\
  69632e305818a119ea6083014812010000aabbccdd4830820100deadbeef6b65\
  6e762e616363656c2e305902a5a119ea608302736170706c69636174696f6e2f\
  6561742b637774590288d83dd2845850a301382203736170706c69636174696f\
  6e2f6561742b637774182282382a5830b7a900ce4d95ace6ea3b75b6cc82744f\
  300e940472f95f1113da57c424155a35ec5c6c0bf6a7d0e493aaae157dc9891a\
  a1182159018f3082018b30820110a003020102020102300a06082a8648ce3d04\
  0303301f311d301b06035504030c14436f6d706f736974652045415420446576\
  696365301e170d3236303130313030303030305a170d33353031303130303030\
  30305a301f311d301b06035504030c14436f6d706f7369746520454154204465\
  766963653076301006072a8648ce3d020106052b810400220362000408d99905\
  7ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86e\
  be0e64f85b96a9c75295df618e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875\
  bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80a320301e\
  300c0603551d130101ff04023000300e0603551d0f0101ff040403020780300a\
  06082a8648ce3d0403030369003066023100e8b3fc58e9c4176767c93e285dcc\
  47fc7896ed6fffa0507686e0ae8cd1843ffbf9819120dbc1197ab481bb3fb54c\
  5f40023100bbe55554d1806236717271f0bea0767109b1a31f57a236ee455569\
  d1a72fb1d3e2fb3aa3d17a8cea6f14a79ff68a0cdb5839a20a58200001020304\
  05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1901005101\
  222222222222222222222222222222225860769f68a04a9cb32623612ee8771f\
  6fc8583135d2272ef9269157b78582031201f2e1efcd9d38bf52d13c25cbb61e\
  74f0f4da21f6608c8a31e6341c63ddd6f9f744e4abde132395f5bca83d098c71\
  c715937f1c339cc6891d4652a8feaed85d79
~~~

# Collected CDDL {#appendix-cddl}

The following CDDL collects the definitions in this document. Values 60000 and
60001 are temporary stand-ins used only to make this Internet-Draft and its
examples mechanically testable; they are not IANA allocations and
implementations MUST NOT treat them as stable claim keys.

~~~ cddl
composite-bundle = #6.602([
  main-token: bstr .cbor composite-eat,
  detached-claims-sets: {
    + env-id => bstr .cbor detached-claims-set
  }
])

composite-eat = #6.61(#6.18([
  protected: bstr .cbor protected-headers,
  unprotected: unprotected-headers,
  payload: bstr .cbor composite-eat-claims,
  signature: bstr
]))

protected-headers = {
  1: -35,
  3: "application/eat+cwt",
  34: certificate-thumbprint
}

certificate-thumbprint = [ -43, bstr .size 48 ]

unprotected-headers = {
  33: cose-x509-chain
}

cose-x509-chain = bstr / [ 2* bstr ]

composite-eat-claims = {
  10: bstr .size 32,
  265: general-uri,
  256: bstr .size (7..33),
  273: measurements-type,
  266: submods-type,
  ? TBD_PLATFORM_CORIM_ID => general-uri
}

measurements-type = [ + lead-attester-measurement ]

lead-attester-measurement = [
  content-format: uint .le 65535,
  value: bstr
]

submods-type = { + env-id => detached-submodule-digest }

detached-submodule-digest = [
  hash-alg: -43,
  digest: bstr .size 48
]

detached-claims-set = {
  TBD_NATIVE_EVIDENCE => native-evidence
}

native-evidence = spdm-evidence / device-eat-evidence

spdm-evidence = [
  evidence-type: 1,
  signed-measurements: bstr,
  cert-chain: bstr,
  ? vca: bstr
]

device-eat-evidence = [
  evidence-type: 2,
  token-format: tstr,
  device-token: bstr
]

env-id = tstr .size (5..64)

general-uri = tstr

TBD_NATIVE_EVIDENCE = 60000
TBD_PLATFORM_CORIM_ID = 60001
~~~

`general-uri` above is the CBOR URI representation from {{RFC9711}}, reduced to
its `tstr` wire type so this stand-alone grammar has no external CDDL imports.

# Acknowledgments
{:numbered="false"}

The authors thank the design and implementation reviewers whose feedback
improved the architecture, encoding, and verification procedures described in
this document. Individual acknowledgments will be added as review continues.
