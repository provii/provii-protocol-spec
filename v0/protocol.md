# Provii: A Privacy-Preserving Age Verification Protocol

| Field | Value |
|---|---|
| Document identifier | `provii-crypto-protocol-0.1` |
| Version | 0.1.0 |
| Status | Stable |
| Date | 2026-05-30 |
| Canonical URL | `https://spec.provii.app/v0/protocol` |
| Source repository | `https://github.com/provii/provii-protocol-spec/tree/v0.1.0` |
| Errata | `https://github.com/provii/provii-protocol-spec/issues` |
| Authors | Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust (ABN 61 633 823 792), PO Box 169, St Arnaud VIC 3478, Australia |
| Contact | spec@provii.app |

---

## Abstract

Provii is a zero knowledge protocol for age-threshold verification. A holder with a date of birth credential, issued once by a trusted third party that has already completed KYC or equivalent identity proofing on the holder, proves to a Verifier that the committed date of birth satisfies an age threshold: either a minimum (for example "at least 18 years old") or a maximum (for example "under 13 years old"). The Verifier returns a binary pass/fail result to the Relying Party that initiated the verification; the Relying Party receives only this result and never sees the proof or any of its public inputs. The Verifier sees the proof and its public inputs, including a per-credential nullifier used to maintain a ban list for abusive or compromised credentials, but does not learn the date of birth, the credential signature, the holder's identity, or any other attribute bound into the credential. The Issuer is not contacted at verification time.

A single arithmetic circuit evaluates both directions via a public selector bit that conditions operand ordering, so one proving key and one verifying key cover both predicates for a given circuit version; trusted-setup rotation or a circuit-constants bump produces a new key pair (Section 6.4, Section 13.7). Proofs are 192 bytes. The protocol uses Groth16 over BLS12-381 with a Jubjub-embedded credential signature based on RedJubjub, Pedersen commitments for the date of birth, Ed25519 attestations from the Issuer, and Blake2s-256 and SHA-256 for hashing. Groth16 requires a per-circuit trusted setup (Section 17.3). None of the cryptographic primitives used here is post-quantum secure; this specification assumes a pre-quantum threat model. Section 17.3 describes the integrity dependency on the trusted-setup ceremony and the operator's transcript publication obligations.

This document specifies the normative cryptographic constructions, wire formats, protocol flows, and conformance requirements. Interoperability across implementations is demonstrated via the normative test vectors in Appendix A. Privacy properties are discussed in Section 18.

---

## Status of This Memo

This document is a stable, version 0.1.0 specification of the Provii age verification protocol, published by Maelstrom AI Pty Ltd. It is intended for cryptographic engineers, security auditors, wallet implementers, verifier operators, identity issuers, and integrators of age verification into web and mobile services.

The version number is fixed for the lifetime of this document. Backward incompatible changes are published as v0.1 or later. Backward compatible additions, where possible, are published as v0.2, v0.3, and so on. Errata that do not change normative behaviour are filed at the errata URL above and reflected in patch revisions of this document with the same version number.

To cite this specification, use:

> Maelstrom AI Pty Ltd, "Provii: A Privacy-Preserving Age Verification Protocol", `provii-crypto-protocol-0.1`, version 0.1.0, May 2026.

To report errata, file an issue at the errata URL with the section number, the line of text in question, and a reproduction or pointer to the relevant source artefact. Errata that affect security MUST be reported privately to security@provii.app before public disclosure.

This document is normative. Where the prose conflicts with the open source reference implementation, the prose in this document governs the protocol; the implementation shall be updated to match. Where the prose contains errors of fact about cryptographic primitives borrowed from other specifications ([ZcashSapling], [RFC7693], [RFC8032], [RFC7636]), those external specifications govern.

---

## Copyright and Licence Notice

Copyright (c) 2026 Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust. All rights reserved.

This document is licensed under the Creative Commons Attribution 4.0 International Licence (CC BY 4.0). The full text of the licence is available at `https://creativecommons.org/licenses/by/4.0/`. You are free to share and adapt this document for any purpose, provided you give appropriate credit, link to the licence, and indicate if changes were made.

### Patent Statement

The Provii privacy-preserving age verification protocol is the subject of Australian Provisional Patent Application No. 2026901546, filed 26 February 2026 by Maelstrom AI Pty Ltd ("the Applicant"). No patent has yet been granted; the application is pending. The Applicant may pursue national-phase grants in additional jurisdictions within applicable priority periods.

The Applicant hereby grants, to any person implementing this specification, a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable (except as stated below) licence under any patent claims that are or may become owned or controlled by the Applicant and that are necessarily infringed by implementing this specification, to make, have made, use, offer to sell, sell, import and otherwise transfer such implementations.

If You institute patent litigation against Maelstrom AI Pty Ltd or any other implementer of this specification alleging that this specification or an implementation thereof constitutes direct or contributory patent infringement, then the patent licence granted to You under this section shall terminate as of the date such litigation is filed.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Terminology and Conventions](#terminology-and-conventions)
3. [Protocol Overview](#protocol-overview)
4. [Curve Parameters](#curve-parameters)
5. [Domain Separation Tags](#domain-separation-tags)
6. [System Constants](#system-constants)
7. [Hash Function Specifications](#hash-function-specifications)
8. [RedJubjub Signature Scheme](#redjubjub-signature-scheme)
9. [Pedersen Commitment Scheme](#pedersen-commitment-scheme)
10. [Ed25519 Attestation Scheme](#ed25519-attestation-scheme)
11. [Issuance Protocol](#issuance-protocol)
12. [Age Verification Circuit](#age-verification-circuit)
13. [Prover and Verifier Protocols](#prover-and-verifier-protocols)
14. [Verification Protocol](#verification-protocol)
15. [Wire Formats](#wire-formats)
16. [Conformance](#conformance)
17. [Security Considerations](#security-considerations)
18. [Privacy Considerations](#privacy-considerations)
19. [IANA Considerations](#iana-considerations)
20. [References](#references)
21. [Appendix A: Test Vectors](#appendix-a-test-vectors)
22. [Appendix B: Informative Examples](#appendix-b-informative-examples)
23. [Appendix C: Data Structures](#appendix-c-data-structures)
24. [Appendix D: Dependency Versions](#appendix-d-dependency-versions)
25. [Appendix E: Deviations from Zcash](#appendix-e-deviations-from-zcash)
26. [Appendix F: Deferred to Future Versions](#appendix-f-deferred-to-future-versions)
27. [Appendix G: Acknowledgements](#appendix-g-acknowledgements)
28. [Authors' Addresses](#authors-addresses)

---

## 1. Introduction

### 1.1 Motivation

Age restriction is a common requirement in online services: alcohol, gambling, adult content, financial products, and increasingly, mainstream social platforms. The default approach is to ask the user for a copy of a government issued identity document, or to delegate the check to a third party that does so. Both approaches transfer a complete identity record, including name, photograph, address, and document number, in order to answer a single question whose true answer is one bit: is the user old enough.

The asymmetry is severe. The Relying Party only needs the bit. The user pays in identity exposure, ongoing breach risk, and the loss of a clean separation between unrelated services. The Verifier, who must store some record to satisfy regulators, accumulates a high value target.

Provii is a protocol that returns to the Relying Party only the answer to the age question. The user's wallet holds a credential issued once by a trusted third party that has already completed KYC or equivalent identity proofing on the user. For each verification request, the wallet generates a zero knowledge proof that the credential commits to a date of birth satisfying the age predicate. The Relying Party learns only the binary verification result and the age threshold it requested. It learns no date of birth, no document number, no identity, no nullifier, and no proof internals. The Verifier sees the proof and its public inputs (one of which is a per-credential nullifier used for credential ban enforcement) but cannot recover any identifying attribute from them.

### 1.2 Approach

Provii is built on four cryptographic ideas, each well established. A Pedersen commitment hides the date of birth as a point on the Jubjub curve, with the hiding property derived from 128 bits of wallet-supplied randomness. A credential signature, computed by the Issuer using a custom RedJubjub instantiation over the same Jubjub curve, binds the commitment to the Issuer's verifying key in a form that can be verified inside an arithmetic circuit. A Groth16 zero knowledge proof over BLS12-381 attests, in 192 bytes regardless of statement complexity, that the prover holds an opening of the commitment, that the commitment is signed by the declared issuer verifying key, and that the committed date of birth satisfies a public age predicate. A separate Ed25519 attestation, also signed by the Issuer, binds each issuance to the authenticated Issuing Party session that supplied the date of birth.

The Ed25519 attestation is the bridge between the Issuing Party's KYC record and the Issuer's blind-issuance endpoint. An Issuing Party (bank, telco, government agency) authenticates its user through its own IdP, resolves a verified `dob_days` from its KYC record, and calls the Issuer over an HMAC-SHA256 authenticated channel to request an attestation. The Issuer mints a 32 byte single-use nonce, signs a message over `dob_days`, the Issuer's identifier, a timestamp, the nonce, and the Issuing Party's session identifier, and returns the attestation to the Issuing Party. The Issuing Party then delivers the attestation to the Wallet via a platform deep link. When the Wallet later calls the Issuer's blind-issuance endpoint with the attestation and 128 bits of commitment randomness, the Issuer verifies its own signature as proof that the date of birth originated from an authenticated Issuing Party session. The Issuer then computes the Pedersen commitment server side and returns a RedJubjub-signed credential. The Wallet supplies the randomness; the Issuer supplies the attested date of birth. Only the Issuer can produce a valid attestation or credential, and no combination of parties can produce a credential committing to a date of birth different from the one the Issuer attested to.

The protocol operates entirely without persistent user accounts at the Verifier. Each verification request begins with a fresh challenge containing a 32 byte `rp_challenge`, an origin string, an age threshold, and a PKCE code challenge. The Wallet returns a proof bound to that challenge. Replay is prevented by short challenge expiry, single-use challenge consumption, and a 32 byte submit secret returned only to the Relying Party. A deterministic per-credential nullifier is also emitted as a public input; this is used by the Verifier for credential ban enforcement, not for replay prevention.

### 1.3 Parties

The protocol involves five roles. Two are Provii-operated services: the Issuer (issues attestations and credentials) and the Verifier (verifies proofs). Two are third-party customer roles: the Issuing Party (authenticates users and requests attestations from the Issuer) and the Relying Party (consumes verification results). The fifth is the user-controlled Wallet, which stores the credential and generates proofs on demand. Section 3.1 describes the five roles in detail.

Section 3 develops this model further. Section 11 specifies the issuance protocol as a numbered flow. Section 14 specifies the verification protocol as a numbered flow.

### 1.4 Protocol Layers

The protocol is organised in layers, each addressed by a distinct part of this document. The cryptographic layer specifies the primitives: BLS12-381 and Jubjub curves, the Pedersen commitment, the RedJubjub signature scheme, Ed25519 attestations, Blake2s-256 and SHA-256 hashing. It is covered in Sections 4 through 10.

The circuit layer specifies the Groth16 R1CS arithmetic circuit that proves the conjunction of commitment opening, in circuit signature verification, and age comparison. It is covered in Section 12.

The protocol layer specifies the off circuit flows: nonce generation, PKCE construction, RP binding, challenge issuance, proof submission, verification, and result redemption. It is covered in Sections 11, 13, and 14.

### 1.5 Document Scope

This document specifies the wire protocol and the cryptographic constructions necessary to interoperate with conforming Provii implementations. It does not specify a particular network transport. HTTP over TLS 1.3 is the expected transport for Provii deployments, but the cryptographic protocol does not depend on it.

This document also does not specify the identity proofing process used by an Issuer to determine a user's date of birth. That process is governed by the Issuer's regulatory environment. Provii begins after the Issuer has decided what date of birth to attest to.

This document does not specify storage formats for wallet credentials beyond the requirement that the wallet preserve the credential, the date of birth, and the commitment randomness across proof generations. Implementations are expected to store these in platform secure storage (for example, the iOS Keychain or the Android Keystore).

Provii is distinct from W3C Verifiable Credentials [W3CVC] and ISO/IEC 18013-5 mobile driving licence [ISO18013-5]; see those specifications for their respective scopes. Provii's credential format is purpose specific and targets a different deployment model.

### 1.6 Document Structure

Section 2 establishes terminology and the requirements language used throughout. Section 3 presents an architectural overview of the protocol with diagrams. Sections 4 through 10 specify cryptographic primitives. Sections 11 through 14 specify protocol flows. Section 15 consolidates wire formats. Section 16 defines conformance. Sections 17 and 18 address security and privacy. Section 20 lists references. The appendices contain test vectors, worked examples, language specific data structure definitions, dependency versions, deviations from Zcash, acknowledgements, and author contact details.

---

## 2. Terminology and Conventions

### 2.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

When these keywords appear in lower case, they are not normative; they have their plain English meaning.

### 2.2 Glossary

The following terms are used throughout this document with the precise meanings given here.

**Attestation.** A signed statement by the Issuer asserting a particular date of birth for a Wallet at a particular point in time. In Provii, attestations are signed with Ed25519 and issued in response to an authenticated request from an Issuing Party. See Section 10.

**`challenge_id`.** The identifier assigned by the Verifier to a newly minted challenge. A UUIDv4 in its 36-character canonical hyphenated form ([RFC9562]). Used by the Wallet when submitting a proof (Section 14.5) and by the Relying Party when redeeming the result (Section 14.7).

**Commitment.** A 32 byte compressed Jubjub point produced by the Pedersen commitment construction in Section 9. Hides a date of birth and 128 bits of randomness. Computed by the Issuer during issuance and embedded in the Credential. The opening (date of birth and randomness) is held only by the Wallet.

**Credential.** The signed object returned by the Issuer to the Wallet at the end of issuance. Contains a version byte, key identifier, commitment, issued at and expires at timestamps, a schema identifier, the issuer verifying key, and a RedJubjub signature over the credential prehash.

**Cutoff Days.** A signed 32 bit integer giving a date as the count of days since the Unix epoch (1970-01-01 UTC). Used as the age threshold in a verification request. A user is "Over" the threshold when `cutoff_days >= dob_days` and "Under" the threshold when `dob_days >= cutoff_days`. Bounded to `[-36525, +36525]` (100 years either side of epoch); see Section 14.

**Direction Bit.** A single Boolean public input to the age verification circuit. `1` (true) selects the Over comparison; `0` (false) selects the Under comparison. The circuit is identical for both directions; only the conditional swap inputs change.

**`dob_days`.** A signed 32 bit integer representing the attested date of birth as the count of days since the Unix epoch (1970-01-01 UTC). Negative values represent pre-1970 dates. Appears in the Ed25519 attestation (Section 10.2) and in the Wallet witness (Section 12.4). Bounded to `[-36525, +36525]` (100 years either side of epoch) at issuance; see Section 10.2.

**Domain Separation Tag (DST).** A constant byte string included in a hash or signature input to ensure that outputs of one protocol step cannot be confused with outputs of another. Section 5 enumerates all DSTs.

**Identity Provider (IdP).** The external party that proofs the user's identity and determines the date of birth that will be supplied to the Issuing Party. The IdP holds no Provii signing keys; its role ends once it has communicated the verified `dob_days` to the Issuing Party. The IdP is out of scope for cryptographic conformance; its proofing process is governed by the Issuing Party's regulatory environment.

**Issuer.** The Provii-operated server that holds the Ed25519 attestation signing key and the RedJubjub credential signing key. On receipt of an authenticated request from an Issuing Party containing a verified `dob_days`, the Issuer signs an Ed25519 attestation and returns it to the Issuing Party. On receipt of an attestation plus wallet randomness from the Wallet, the Issuer computes a Pedersen commitment and returns a RedJubjub signed Credential. The Issuer's RedJubjub verifying key is published to a key registry consulted by the Verifier.

**Issuing Party.** A third-party customer backend (bank, government agency, telecommunications provider, or similar) that authenticates users via its own IdP and then authenticates to the Issuer over an HMAC-SHA256 channel to obtain Ed25519 attestations for its users. The Issuing Party holds no Provii signing keys; it holds its users' dates of birth in its own KYC systems and passes verified `dob_days` values to the Issuer on a per-attestation basis.

**Nullifier.** A deterministic 32 byte value derived from a Credential's commitment via a second Pedersen hash with a distinct personalisation tag. The Nullifier is a public input to every proof generated from the Credential: the same Credential always produces the same Nullifier. The Verifier uses the Nullifier to maintain a ban list of abusive or compromised Credentials (Section 9.4, Section 14.9). The Nullifier is visible to the Verifier only; it is not returned to the Relying Party.

**PKCE.** Proof Key for Code Exchange, [RFC7636]. Used in Provii to bind the party that receives the verification result to the party that initiated the challenge. Provii uses the S256 method exclusively.

**Proof.** A 192 byte Groth16 proof over BLS12-381, attesting to satisfaction of the age verification circuit (Section 12). The size is fixed regardless of the complexity of the underlying circuit.

**Prover.** The party that runs the Groth16 prover. In Provii, this is always the Wallet.

**Proving Key.** The Groth16 prover's parameters. Approximately 50 megabytes for the current circuit. Distributed by the Issuer or a CDN to Wallets that need to generate proofs.

**Public Inputs.** The eight BLS12-381 scalar field elements supplied to the Groth16 verifier alongside the proof. They are the multipacked encoding of the direction bit, biased cutoff days, RP hash, issuer verifying key, and credential nullifier (Section 12.3).

**`r_bits`.** The 128-bit commitment randomness sampled by the Wallet during issuance and supplied to the Pedersen commitment (Section 9.1). Stored by the Wallet in platform secure storage alongside `dob_days` and the SignedCredential; never transmitted after issuance. The circuit accepts exactly 128 bits (Section 9.3 Profile A).

**Relying Party (RP).** A third-party customer website or application that consumes verification results. The Relying Party requests a challenge from the Verifier (directly for Expert integrations, or via a Provii-operated intermediary for Simple integrations; see Section 14), presents the challenge to the Wallet (typically via QR code or deep link), and redeems the result via PKCE.

**`rp_challenge`.** A 32 byte value derived by the Verifier as `SHA-256(origin || nonce || "provii.challenge.v0")` where `nonce` is 32 bytes from a CSPRNG. Transmitted through the Relying Party to the Wallet, and relayed by the Wallet back to the Verifier in the proof submission (Section 14.5). Distinct from `rp_hash`, which is the Blake2s-256 wrap of `rp_challenge` consumed as a circuit public input.

**RP Hash.** A 32 byte circuit public input that binds the proof to a specific challenge. Computed as `Blake2s-256(rp_challenge)`. See Section 13.2.

**Submit Secret.** A 32 byte CSPRNG sourced token issued by the Verifier alongside a challenge. The Verifier returns it only to the Relying Party. The Wallet receives it through the Relying Party and includes it in the proof submission. Constant time comparison against the stored value gates the submission.

**Verifier.** The Provii-operated server that verifies Groth16 proofs against its issuer key registry, enforces challenge expiry, maintains the nullifier ban list, and notifies the Relying Party of the verification result via PKCE redemption. Provii operates a single Verifier; the spec does not contemplate multiple Verifiers.

**Verifying Key (VK).** Two distinct keys are referred to by similar names in this document; context disambiguates.

(a) The *Issuer Verifying Key* (`issuer_vk`) is a 32 byte compressed Jubjub point that verifies RedJubjub signatures on Credentials. It is a circuit public input.

(b) The *Groth16 Verifying Key* is a Bellman serialised verifying key (1732 bytes for the current circuit) used by the Verifier to verify proofs. It is identified by a 32 bit `vk_id`.

**`vk_id`.** A 32 bit identifier for a Groth16 verifying key, derived via Section 13.7. Embedded in every proof submission (Section 14.5) so the Verifier can route the proof to the correct verifying key in its `VK_REGISTRY`. The v0.1 production `vk_id` is `914153247`.

**Wallet.** The user controlled software (typically mobile) that stores Credentials, generates Proofs, and performs the Wallet side steps of the protocol.

**Witness.** The private inputs to the Groth16 prover: the date of birth, the commitment randomness, and the credential signature. Held only by the Wallet at proving time. The witness is never bundled into a transmitted message, and no component is revealed to the Verifier or Relying Party. Individual fields are exchanged between the Wallet and the Issuer during issuance (Section 11).

**Zero Knowledge Proof (ZKP).** A proof that a statement is true that reveals no information about the witness beyond that fact. Provii uses Groth16 [Groth16] over BLS12-381.

### 2.3 Notation

| Symbol | Meaning |
|---|---|
| `\|\|` | Byte concatenation |
| `LE(x, n)` | Little endian encoding of integer `x` in `n` bytes |
| `BE(x, n)` | Big endian encoding of integer `x` in `n` bytes |
| `bits_le(x, n)` | Little endian bit decomposition of `x` into `n` bits, byte little endian then bit little endian within each byte |
| `Fr_J` | Scalar field of the Jubjub curve, approximately 251 bits |
| `Fr_B` | Scalar field of BLS12-381, approximately 255 bits |
| `G` | The Sapling spending key generator point on the Jubjub curve. See Section 4.3 |
| `[s]P` | Scalar multiplication of point `P` by scalar `s` |
| `H_b2s(pers, data)` | Blake2s-256 with the 8 byte personalisation parameter `pers` and message `data`, producing 32 bytes |
| `H_b2s(data)` | Blake2s-256 over `data`, with no personalisation, producing 32 bytes |
| `H_ped(pers, bits)` | The Zcash Sapling Pedersen hash with personalisation `pers` over bit vector `bits`, producing a Jubjub subgroup point |
| `H_sha256(data)` | SHA-256 over `data`, producing 32 bytes |
| `wide_reduce_J(x)` | Reduce a 64 byte input `x` to an element of `Fr_J` via `from_bytes_wide` |
| `compress(P)` | Canonical 32 byte compressed encoding of a Jubjub point `P` |
| `b"x"` | A literal byte string with the ASCII bytes of `x` |
| `0x00^n` | A constant byte string of `n` zero bytes |
| `len(x)` | The byte length of `x` |

### 2.4 Byte Ordering

Byte ordering is not uniform across the protocol. Each construction below names its endianness explicitly. The conventions are:

- **Credential prehash** (Section 8.2): `iat` and `exp` use big endian. All other length and version fields are single bytes.
- **Ed25519 attestation message** (Section 10.2): `dob_days` (i32) and `timestamp` (u64) use little endian. A u64 suffices because Unix epoch seconds are always non-negative. For any non-negative value representable in both, the 8 byte LE encoding of a u64 is byte-identical to the 8 byte LE encoding of an i64 with the same numeric value; this equivalence lets implementations that store timestamps as signed integers emit the canonical wire bytes without conversion.
- **Circuit public inputs** (Section 12.3): all values use little endian byte order, then little endian bit order within each byte.
- **Jubjub scalars and points**: canonical little endian representations as defined by the `jubjub` crate. Points use the compressed Edwards form (v coordinate plus sign bit).
- **BLS12-381 scalars and points**: as defined by the `bls12_381` crate; not directly user visible at the wire level.

The discrepancies between in-circuit big endian (for `iat` / `exp`) and elsewhere little endian are deliberate and historical. Implementations MUST follow each section's stated convention exactly.

### 2.5 Byte and Bit Ordering for Multipacking

Where a 32 byte value is packed into a sequence of BLS12-381 field elements via the multipack algorithm, the byte order is the literal byte order of the value as it would appear on the wire (little endian for `cutoff_days` and `direction`, network order for raw byte arrays such as `rp_hash`, `issuer_vk`, and `cred_nullifier`). Within each byte, bits are little endian (least significant bit first). The bit vector is then chunked into 254 bit chunks (the BLS12-381 scalar capacity), each chunk forming one field element. Section 12.3 specifies the resulting eight element vector.

### 2.6 Encoding of Strings on the Wire

Where a string field crosses a wire (origins, issuer identifiers, key identifiers, schemas), the encoding is UTF-8. Length prefixes are explicit and stated for each case. Implementations MUST NOT normalise case, trim whitespace, NFC normalise, or punycode normalise strings before hashing. Origin strings MUST be compared byte for byte.

### 2.7 Base64 Conventions

Where base64 encoding is used for transport (challenge identifiers, RP challenge bytes, submit secrets, proof bytes in JSON), the encoding is base64url with no padding (`-` and `_` substituted for `+` and `/`, no trailing `=` characters). Decoders MUST reject inputs containing padding characters, non-URL-safe characters, or whitespace. A 32 byte value encodes to exactly 43 characters.

Decoders MUST reject base64url encodings whose final character carries non-zero padding bits, per [RFC4648] Section 3.5. A 32-byte value admits exactly one valid 43-character base64url-no-pad encoding; a 64-byte value admits exactly one valid 86-character encoding; a 192-byte value admits exactly one valid 256-character encoding.

Where hex encoding is used (typically for human display in test vectors and configuration), the encoding is lower case ASCII hex, two characters per byte, with no separators. A 32 byte value encodes to exactly 64 characters.

The wire format MUST use base64url with no padding for binary fields embedded in JSON. Hex is used in this specification's tables and examples for human readability.

---

## 3. Protocol Overview

### 3.1 Protocol Parties

Provii involves two Provii-operated services (the Issuer and the Verifier), two third-party customer roles (the Issuing Party and the Relying Party), and the user-controlled Wallet. The short names belong to the Provii-operated services; the "-ing Party" names belong to the customer roles that depend on them.

The Issuer holds the Ed25519 attestation signing key and the RedJubjub credential signing key; it signs attestations on behalf of Issuing Parties and signs credentials for Wallets. The Issuing Party authenticates its users via its own IdP and KYC systems and calls the Issuer over an HMAC-SHA256 authenticated channel to obtain attestations. The Wallet holds the user's credential and is the only party that ever sees the date of birth in cleartext after issuance. The Relying Party requests verification results for its own gating purposes. The Verifier verifies Groth16 proofs against its issuer key registry and returns results to Relying Parties.

```
        +------------------+       +--------------------+
        |  Issuing Party   |<----->|      Issuer        |
        |  (bank, DMV,     |  HMAC |  (Provii-operated; |
        |   telco; holds   | auth  |   holds Ed25519 +  |
        |   user DOB)      |       |   RedJubjub keys)  |
        +------------------+       +--------------------+
                |                            ^
     deep link  |                            | attestation +
     to Wallet  |                            | r_bits -> blind
     with atn   v                            | issuance
        +------------------+                 |
        |      Wallet      |-----------------+
        |  (mobile device; |
        |  stores Cred +   |
        |  DOB + r_bits)   |
        +------------------+
            ^      |
            |      | Groth16 proof + public inputs
QR / deep   |      v
link        |   +--------------------+
            |   |     Verifier       |
            |   |  (Provii-operated; |
            |   |   verifies proof,  |
            |   |   checks ban list, |
            |   |   PKCE redeem)     |
            |   +--------------------+
            |             ^
            |             | challenge / result via PKCE
            |             v
            |   +--------------------+
            +-->|   Relying Party    |
                | (website / app;    |
                |  consumes result)  |
                +--------------------+
```

### 3.2 Knowledge Boundary Matrix

The following table summarises what each party learns under correct operation.

| Information | Issuing Party | Issuer | Wallet | Verifier | Relying Party |
|---|---|---|---|---|---|
| User's date of birth | Yes (from its own KYC) | Yes (during issuance only; discarded immediately after credential is signed) | Yes (stored locally) | No | No |
| Commitment randomness `r_bits` | No | Yes (during issuance only; discarded immediately) | Yes (stored locally) | No | No |
| Pedersen commitment `c` | No | Yes (computes it) | Yes (in credential) | No (not transmitted as such; appears only inside the proof witness) | No |
| Nullifier | No | No | Yes (computes off circuit) | Yes (public input) | No |
| Issuer verifying key | No | Yes (its own) | Yes (in credential) | Yes (registry) | No |
| RP hash | No | No | Yes (computes off circuit) | Yes (recomputes) | No |
| Cutoff days | No | No | Yes | Yes | Yes (from its own Verifier policy) |
| Direction (Over / Under) | No | No | Yes | Yes | Yes (derived server side from the RP's origin policy and returned to the RP in the challenge response) |
| Proof bytes | No | No | Yes (generates) | Yes (verifies) | No |
| Verification result (pass/fail) | No | No | Yes (locally) | Yes | Yes |

The Wallet learns nothing about the Verifier or Relying Party identity beyond what the Wallet user observed when scanning a QR code or following a deep link. The Verifier learns the nullifier and uses it for replay detection against its ban store; the Relying Party never learns the nullifier. The Relying Party learns only the binary verification result and the age threshold it requested.

### 3.3 High Level Issuance Flow

Issuance has two HTTP round trips. The first is Issuing Party to Issuer, producing an attestation. The second is Wallet to Issuer, producing a credential. Between the two, the Issuing Party delivers the attestation to the Wallet via a platform deep link.

```
Step A.  The user authenticates to the Issuing Party's IdP and the
         Issuing Party resolves a verified dob_days from its KYC data.
Step B.  The Issuing Party calls the Issuer over an HMAC-SHA256
         authenticated channel, passing dob_days plus the requesting
         Issuing Party's CLIENT_ID.
Step C.  The Issuer mints a 32 byte nonce and signs an Ed25519
         attestation containing dob_days, the Issuing Party's
         identifier, a timestamp, and the nonce. The nonce is not
         recorded at this point; it is consumed at blind-issuance
         time (Step G).
Step D.  The Issuer returns the attestation to the Issuing Party.
Step E.  The Issuing Party constructs a deep link containing the
         attestation and invokes the Wallet.
Step F.  The Wallet receives the deep link, generates 128 bits of
         commitment randomness from a platform CSPRNG, and calls the
         Issuer's blind-issuance endpoint with the attestation and
         r_bits.
Step G.  The Issuer verifies the Ed25519 signature, freshness bounds,
         and nonce single use (the nonce is recorded in the consumed-
         nonce store at this point, with TTL
         ATTESTATION_NONCE_TTL_SECONDS); computes
         c = PedersenCommit(dob_days, r_bits).
Step H.  The Issuer constructs CredMsgV2(v, kid, c, iat, exp, schema),
         computes the credential prehash, hashes it with Blake2s-256,
         signs the hash with its RedJubjub credential signing key, and
         self verifies the signature off circuit.
Step I.  The Issuer returns the SignedCredential (CredMsgV2 +
         issuer_vk + signature) to the Wallet.
Step J.  The Issuer discards dob_days and r_bits.
Step K.  The Wallet stores the credential, dob_days, and r_bits in
         platform secure storage.
```

Section 11 specifies this flow normatively. The integrity property "wallet cannot lie about its date of birth" derives from the Issuer computing the commitment server side over the attested `dob_days`, with only the randomness contributed by the Wallet. The hiding property derives from the Wallet supplying the randomness, which the Issuer then discards.

### 3.4 High Level Verification Flow

Verification has two integration profiles. In the Simple profile, the Relying Party calls a Provii-operated HTTP intermediary (the simple verification service) which relays to the Verifier; origin policy and `proof_direction` derivation are handled by the intermediary. In the Expert profile, the Relying Party calls the Verifier directly using HMAC-SHA256 authentication and supplies a PKCE `code_challenge`. Section 14 specifies both profiles normatively. The steps below describe the Expert profile; the Simple profile is equivalent except that the Relying Party's request and result flow through the simple verification service rather than directly to the Verifier.

```
Step 1.  The Relying Party calls the Verifier requesting a challenge
         with origin, age threshold (translated to cutoff_days), TTL,
         and a PKCE code_challenge. The Verifier looks up the origin's
         policy record to determine the proof_direction.
Step 2.  The Verifier generates challenge_id (UUIDv4), a 32 byte
         nonce from a CSPRNG, derives rp_challenge as
         SHA-256(origin || nonce || "provii.challenge.v0"),
         generates a 32 byte submit_secret from a CSPRNG, and a
         12-digit numeric short_code.
Step 3.  The Verifier stores a CachedChallenge keyed by challenge_id
         (origin, cutoff_days, proof_direction, verifying_key_id,
         code_challenge, submit_secret, expires_at, state, short_code,
         status_url, verify_url, and further bookkeeping fields; see
         Section 15.9 for the full list).
Step 4.  The Verifier returns to the Relying Party: challenge_id,
         rp_challenge, cutoff_days, verifying_key_id, submit_secret,
         expires_at, proof_direction, short_code, status_url,
         verify_url.
Step 5.  The Relying Party delivers (challenge_id, rp_challenge,
         cutoff_days, verifying_key_id, proof_direction) plus
         submit_secret to the Wallet via QR code (desktop to mobile)
         or deep link (mobile to mobile).
Step 6.  The Wallet performs preflight checks (Section 13.5) and
         computes off circuit: nullifier,
         rp_hash = Blake2s-256(rp_challenge).
Step 7.  The Wallet generates a Groth16 proof using its credential
         witness and the public inputs (direction, biased cutoff,
         rp_hash, issuer_vk, nullifier).
Step 8.  The Wallet submits a SubmitProofRequest to the Verifier:
         { challenge_id, submit_secret,
           proof: { verifying_key_id,
                    public: { cutoff_days, rp_challenge,
                              issuer: { value }, cred_nullifier },
                    proof } }.
Step 9.  The Verifier loads the CachedChallenge, validates
         submit_secret in constant time, recomputes rp_hash, checks
         the nullifier against its ban store, looks up the issuer in
         its allowlist, and verifies the Groth16 proof.
Step 10. The Verifier records the result and transitions the
         CachedChallenge from Pending to ProofOkWaitingForRedeem or
         Failed.
Step 11. The Relying Party redeems the result at
         POST /v0/challenge/:challenge_id/redeem by presenting the
         PKCE code_verifier.
Step 12. The Verifier validates SHA-256(code_verifier) against the
         stored code_challenge in constant time and returns
         { result: "OK", verified: bool } to the Relying Party.
         On redeem, the Verifier transitions the CachedChallenge to
         Verified.
```

Section 14 specifies this flow normatively, including the credential expiry policy enforcement that occurs outside the circuit.

### 3.5 Trust Assumptions

Each party trusts a small, named set of other parties for specific things.

The Wallet trusts the Issuer's RedJubjub credential signing key to attest only to dates of birth that the Issuer in fact received from an authenticated Issuing Party. The Wallet trusts the platform CSPRNG to produce 128 bits of unbiased randomness and trusts the platform secure storage to protect the credential.

The Verifier trusts the Issuer's RedJubjub verifying key, as registered in the Verifier's allowlist, to identify legitimate credentials. The Verifier trusts the integrity of the Groth16 trusted setup that produced the proving and verifying keys for the age circuit, and trusts its own session storage for challenge state and nullifier ban state.

The Relying Party trusts the Verifier to enforce protocol invariants: challenge expiry, nullifier ban enforcement, in-circuit proof verification, off-circuit credential expiry rejection, PKCE single use, and constant-time checks on secret comparisons.

The Issuer trusts the Issuing Party to authenticate the user and to present a `dob_days` that reflects the Issuing Party's own verified KYC record. The authenticated channel (HMAC-SHA256 with a per-Issuing-Party `CLIENT_ID`) binds each attestation request to a specific Issuing Party; the Issuer does not trust unauthenticated callers. The Issuer trusts its own randomness sources, its own signing keys, and its own audit log integrity.

The Issuing Party trusts its own IdP and KYC systems for identity proofing. No cryptographic guarantees of this specification depend on the IdP; the IdP is an operational responsibility of the Issuing Party.

No party trusts the network. All on-the-wire traffic MUST be transported under TLS 1.3 or later. The protocol's cryptographic guarantees do not depend on TLS for confidentiality of the proof or its public inputs (none of those values are secret), but they do depend on TLS to prevent active interception of the submit_secret and the PKCE code_verifier.

### 3.6 Out of Scope

The following are out of scope for this specification.

- The Issuing Party's identity proofing process. The Issuing Party is responsible for ensuring that any dates of birth it presents to the Issuer correspond to real, verified individuals.
- Network transport details. TLS 1.3 is RECOMMENDED but the cryptographic protocol is transport agnostic.
- Wallet user interface design. The protocol is silent on how the Wallet presents proof generation requests to the user, except to the extent that it RECOMMENDS user consent for each verification.
- Credit and metering systems used to bill Issuing Parties and Relying Parties. Such systems are operational concerns layered above this protocol.
- Operational deployment platform details (Cloudflare Workers, AWS, others). The protocol is platform agnostic.
- The Issuer's internal access control on its RedJubjub and Ed25519 signing keys. The protocol assumes those keys are in the Issuer's sole possession and are rotated at the Issuer's discretion.

---

## 4. Curve Parameters

### 4.1 BLS12-381

BLS12-381 is the pairing friendly elliptic curve used as the SNARK backend for Groth16 proofs.

| Parameter | Value |
|---|---|
| Security level | Approximately 128 bits |
| Embedding degree | 12 |
| Scalar field order `r` | `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |
| Scalar field bit length | 255 bits (capacity 254 bits for multipack) |
| Reference library | `bls12_381` crate, version 0.8 |

Implementations MUST use BLS12-381 with the parameters specified in [PairingCurves]. Verifying keys SHALL be encoded using the canonical encoding produced by `bellman::groth16::VerifyingKey::write`, which emits a mix of compressed G1 and G2 encodings per the Bellman 0.14 format [Bellman] (1732 bytes total for the v0.1 deployed VK). Proofs SHALL be encoded using `bellman::groth16::Proof::write`, which uses the compressed Bellman serialisation [Bellman] (see Section 15.5).

### 4.2 Jubjub

Jubjub is a twisted Edwards curve embedded in the BLS12-381 scalar field. Embedding Jubjub inside `Fr_B` makes Jubjub operations efficient when expressed as R1CS constraints in the Groth16 circuit, because Jubjub operations are native field arithmetic in the BLS12-381 scalar field.

| Parameter | Value |
|---|---|
| Security level | Approximately 128 bits |
| Curve equation | `-u^2 + v^2 = 1 + d * u^2 * v^2` (twisted Edwards) |
| Coefficient `d` | As specified in Zcash Sapling protocol [ZcashSapling] |
| Cofactor | 8 |
| Scalar field order `r_J` | `0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7` |
| Scalar field bit length | 251 bits |
| Reference library | `jubjub` crate, version 0.10 |

All Provii operations on Jubjub are restricted to the prime order subgroup. Implementations MUST reject points outside the prime order subgroup at deserialisation. Specifically, a 32 byte input intended to be a Jubjub point MUST decode via `SubgroupPoint::from_bytes` (or equivalent) and MUST be rejected if the decoder reports the point is not in the prime order subgroup, is the identity, or is in canonical encoding range error.

A 32 byte scalar encoding is **canonical** iff it encodes an integer strictly less than `r_J`. The canonical range check is used throughout this specification (for example, Section 8.1) to reject out-of-range scalars at deserialisation.

The cofactor 8 means the full Jubjub curve has eight times as many points as the prime order subgroup. Use of the prime order subgroup eliminates small subgroup attacks.

### 4.3 Spending Key Generator

All RedJubjub operations and the in circuit signature verification gadget use a single fixed generator point `G` on the Jubjub prime order subgroup. This is the Sapling spending key generator.

```
G = SubgroupPoint::from_bytes([
    0x30, 0xb5, 0xf2, 0xaa, 0xad, 0x32, 0x56, 0x30,
    0xbc, 0xdd, 0xdb, 0xce, 0x4d, 0x67, 0x65, 0x6d,
    0x05, 0xfd, 0x1c, 0xc2, 0xd0, 0x37, 0xbb, 0x53,
    0x75, 0xb6, 0xe9, 0x6d, 0x9e, 0x01, 0xa1, 0x57,
])

Hex: 30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a157
```

This is the canonical compressed encoding (v coordinate plus sign bit). The encoding MUST decode to a point in the Jubjub prime order subgroup. Implementations that fail to decode this constant MUST refuse to operate.

The same 32 byte sequence appears in three places in a conforming implementation: the off circuit signing and verification routines; the in circuit signature verification gadget; and the inputs to `compute_circuit_constants_hash` (Section 12.6). Any change to this constant invalidates all existing proving keys and verifying keys.

Source citation: `provii-crypto/crypto-sig-redjubjub/src/lib.rs:47-51`.

### 4.4 Ed25519

Ed25519 [RFC8032] is used for issuer attestations.

| Parameter | Value |
|---|---|
| Security level | Approximately 128 bits |
| Reference library | `ed25519-dalek` crate, version 2.1 |
| Signing key size | 32 bytes |
| Verifying key size | 32 bytes |
| Signature size | 64 bytes |

Ed25519 signatures and keys SHALL be encoded as specified in [RFC8032]. Implementations MUST verify Ed25519 signatures using the strict verification rules of [RFC8032] (no malleability acceptance).

---

## 5. Domain Separation Tags

All cryptographic operations in Provii use distinct domain separation tags (DSTs) to prevent cross protocol attacks. Two operations MUST NOT share a tag. The tags listed in this section are normative and fixed for protocol version 0.1.

### 5.1 Active DSTs

The following DSTs are used by conforming v0.1 implementations.

| Constant | UTF-8 value | Length (bytes) | Hex | Used by |
|---|---|---|---|---|
| `CRED_DST` | `provii.cred.v0` | 14 | `70726f7669692e637265642e7630` | Credential prehash (Section 8.2); circuit constants hash (Section 12.6) |
| `NULLIFIER_DST` | `provii.nullifier.pedersen.v0` | 28 | `70726f7669692e6e756c6c69666965722e706564657273656e2e7630` | Nullifier off circuit (Section 9.4) and in circuit; circuit constants hash |
| `DOB_ATTESTATION_DST` | `provii.attestation.dob.v0` | 25 | `70726f7669692e6174746573746174696f6e2e646f622e7630` | Ed25519 attestation message (Section 10.2) |
| `VK_ID_DST` | `provii.vk.id.v0` | 15 | `70726f7669692e766b2e69642e7630` | Groth16 verifying key identifier derivation (Section 13.7) |
| `PROVII_RJ_PERSONALIZATION` | `ProviiRJ` | 8 | `50726f766969524a` (the eight bytes `50 72 6f 76 69 69 52 4a`) | Blake2s personalisation for the RedJubjub challenge hash (Section 8.4) |
| `PROVII_RJ_NONCE_TAG` | `ProviiRJ/nonce` | 14 | `50726f766969524a2f6e6f6e6365` (the 14 bytes `50 72 6f 76 69 69 52 4a 2f 6e 6f 6e 63 65`) | Prefix for RedJubjub nonce derivation (Section 8.3) |

Two of these constants warrant note. `PROVII_RJ_PERSONALIZATION` is used as the Blake2s `personal()` parameter (a slot in the Blake2s parameter block, not a prefix of the input). `PROVII_RJ_NONCE_TAG` is used as a literal prefix of the input bytes to a Blake2s instance with no personalisation. The two MUST NOT be interchanged. Section 7 distinguishes these two Blake2s call patterns.

### 5.2 Pedersen Personalisations

The Zcash Sapling Pedersen hash prefixes each input bit stream with a six bit personalisation tag. The personalisation is a **sequence of six bits**, not six bytes; it is prepended to the input bits before the windowed Pedersen hash is evaluated. Provii uses two of the Sapling personalisations.

| Personalisation | Six bit prefix | Used by |
|---|---|---|
| `NoteCommitment` | `111111` (six 1-bits) | Pedersen commitment over `dob_bits \|\| r_bits` (Section 9.1) |
| `MerkleTree(num)` | LE bit encoding of `num` over six bits | Nullifier over `NULLIFIER_DST_bits \|\| c_bytes_bits` (Section 9.4), with `num = 0` yielding `000000` |

For Provii's nullifier construction, `MerkleTree(0)` is used, which encodes to the six bits `000000`. More generally, `MerkleTree(num)` encodes `num` (a `usize`) as six little endian bits `(num >> 0) & 1, (num >> 1) & 1, ..., (num >> 5) & 1`; values that do not fit in six bits are outside the Sapling specification and MUST NOT be used.

These six personalisation bits are prepended to the protocol-defined input bit stream, and the combined bit sequence is fed to the Sapling Pedersen hash. Implementations MUST NOT treat the personalisation as six input bytes; doing so would waste 42 bit slots and produce different output points. The byte literal `[0x09, 0x00, 0x00, 0x00, 0x00, 0x00]` that appears in some legacy documentation is a misreading of the Sapling source and is not normative.

Source citation: `sapling-crypto-0.5.0/src/pedersen_hash.rs:22-27` (upstream `Personalization` enum to bit sequence conversion) and `provii-crypto/crypto-circuit-age/src/gadgets/pedersen.rs:31` (in-circuit gadget that prepends the same six bit prefix).

### 5.3 DST Uniqueness

The active DSTs in Section 5.1 are byte distinct and no two share a prefix. Implementations MAY rely on this property. Future revisions of this specification preserve byte distinctness and prefix freedom; new DSTs are chosen such that they are neither a prefix nor an extension of any existing DST.

---

## 6. System Constants

### 6.1 Time Constants

| Constant | Value | Unit | Description |
|---|---|---|---|
| `CHALLENGE_EXPIRY_SECONDS` | 300 | seconds | Challenge validity window (5 minutes) |
| `CLOCK_SKEW_TOLERANCE_SECONDS` | 30 | seconds | Generic clock drift allowance |
| `SESSION_TIMEOUT_SECONDS` | 120 | seconds | Issuance session timeout (2 minutes) |
| `ATTESTATION_MAX_AGE_SECONDS` | 3600 | seconds | Ed25519 attestation freshness window (1 hour) |
| `ATTESTATION_NONCE_TTL_SECONDS` | 7200 | seconds | Nonce single-use store retention floor (2 hours), Section 10.6 |
| `ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS` | 60 | seconds | Maximum permitted clock skew when an attestation timestamp is ahead of local time |
| `MAX_VALIDITY_SECONDS` | 3 153 600 000 | seconds | Hard ceiling on credential lifetime (`exp - iat`); 36 500 days (approximately 100 years, using 86 400 seconds per day). The RECOMMENDED default for general deployments is 7 300 days (20 years, 630 720 000 seconds) so the credential ages with the user (Section 17.12). |

The `SESSION_TIMEOUT_SECONDS` value is given here in seconds. The reference implementation declares the equivalent constant as `SESSION_TIMEOUT_MS = 120_000` (milliseconds). Implementations MUST treat the canonical value as 120 seconds and convert to other units as needed for their environment.

The `ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS = 60` value differs from the generic `CLOCK_SKEW_TOLERANCE_SECONDS = 30` because Ed25519 attestation timestamps cross a trust boundary (the Issuing Party's clock vs the Issuer's clock) and the protocol allows additional slack on the upper bound. Both values are normative and are exported from `provii-crypto/crypto-commons/src/constants.rs`.

**Invariants.** Implementations MUST satisfy:
- `CHALLENGE_EXPIRY_SECONDS > CLOCK_SKEW_TOLERANCE_SECONDS`
- `ATTESTATION_MAX_AGE_SECONDS > ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS`
- `SESSION_TIMEOUT_SECONDS > 0`
- `MAX_VALIDITY_SECONDS > 0`
- `ATTESTATION_NONCE_TTL_SECONDS > ATTESTATION_MAX_AGE_SECONDS`

These values are normative for v0.1 and changing any of them produces a different protocol version.

### 6.2 Size Constants

| Constant | Value | Unit | Description |
|---|---|---|---|
| `NONCE_SIZE` | 32 | bytes | Challenge nonce length |
| `CREDENTIAL_ID_SIZE` | 32 | bytes | Credential identifier length |
| `MAX_CREDENTIAL_SIZE` | 8192 | bytes | Maximum serialised credential |
| `KID_SIZE_BYTES` | 14 | bytes | Fixed key identifier byte length (in circuit) |
| `SCHEMA_SIZE_BYTES` | 12 | bytes | Fixed credential schema byte length (in circuit) |
| `MIN_PEDERSEN_RANDOMNESS_BITS` | 128 | bits | Minimum r_bits length accepted by `validate_commitment_randomness` |
| `MAX_PEDERSEN_RANDOMNESS_BITS` | 1096 | bits | Maximum r_bits length the Sapling Pedersen hash supports above the 32 bit DOB and 6 bit personalisation |
| `MIN_UNIQUE_BYTES_R_BITS` | 8 | bytes | Minimum count of unique byte values across packed r_bits (entropy floor) |
| `SUBMIT_SECRET_SIZE` | 32 | bytes | Anti-spam submission token length (Section 14.2) |

All size constants are normative for v0.1. `MIN_UNIQUE_BYTES_R_BITS` and `SUBMIT_SECRET_SIZE` are normative values defined by this specification regardless of whether the reference implementation exports them as named constants.

Source citations: `provii-crypto/crypto-commons/src/constants.rs` (`MIN_PEDERSEN_RANDOMNESS_BITS`, `MAX_PEDERSEN_RANDOMNESS_BITS`, `NONCE_SIZE`, `CREDENTIAL_ID_SIZE`, `MAX_CREDENTIAL_SIZE`, `KID_SIZE_BYTES`, `SCHEMA_SIZE_BYTES`), `provii-mobile-sdk/crates/core/src/issuance.rs:24` (`R_BITS_LEN`; referenced from Section 9.3), `provii-crypto/crypto-prover/src/lib.rs:1491` (hard-coded `128` length check on the prover side), `provii-crypto/crypto-circuit-age/src/lib.rs:306` (hard-coded `128` length check inside the circuit), `provii-crypto/crypto-commit/src/lib.rs:229` (literal `>= 8` unique-byte check).

### 6.3 Bias Constant

The bias constant maps signed 32 bit integer ordering to unsigned 32 bit integer ordering by flipping the sign bit. It is used to convert `dob_days` and `cutoff_days` (both `i32`) to a form suitable for in-circuit unsigned comparison.

| Constant | Value | Description |
|---|---|---|
| `SIGN_BIAS` | `0x8000_0000` | XOR mask for sign-magnitude to unsigned ordering |

For any signed 32 bit integer `x`, the bias `bias_for_circuit(x) = (x as u32) XOR 0x8000_0000` satisfies `bias(x) < bias(y)` when compared as unsigned 32 bit integers if and only if `x < y` when compared as signed 32 bit integers. Worked values appear in Appendix A.1.

Source citation: `provii-crypto/crypto-commons/src/lib.rs` (`bias_for_circuit`).

### 6.4 Versioning

| Constant | Value | Description |
|---|---|---|
| Credential format version | `2` | The `v` field in CredMsgV2 (Section 8.2) |
| Circuit constants hash version | `v0` | The version tag inside `compute_circuit_constants_hash` (Section 12.6) |
| Protocol version | `0.1.0` | This document |

A change to any constant in Sections 4 through 6 that affects the circuit (curve parameters, generator, DSTs included in the constants hash, the `v0` tag, fixed sizes) MUST bump the circuit constants hash version, MUST regenerate the Groth16 trusted setup, and MUST roll the `vk_id`. Such changes MUST be published as a new protocol version (v1.0 at minimum if backward incompatibility is introduced).

---

## 7. Hash Function Specifications

### 7.1 Blake2s-256 with Personalisation Parameter

Used for the RedJubjub challenge hash (Section 8.4) and inside the in circuit signature verification gadget (Section 12.7 step 8). This call pattern uses the Blake2s `personal` slot of the parameter block, an 8 byte field in the Blake2s parameter block defined by [RFC7693], Section 2.5.

**Reference library.** `blake2s_simd::Params`.

```
H_b2s(pers, data):
    Params::new()
        .hash_length(32)
        .personal(pers)              // pers MUST be exactly 8 bytes
        .to_state()
        .update(data)
        .finalize()
        .as_bytes()                  // 32 bytes
```

The personalisation parameter MUST be exactly 8 bytes. If the source DST is shorter (none of the v0.1 personalisation DSTs are), it MUST be padded with the zero byte to 8 bytes. Implementations MUST NOT prepend the personalisation to the data; the personalisation flows into the Blake2s parameter block, not the message.

The construction is the construction defined in [RFC7693] Section 2.5 with the personalisation field set as described.

### 7.2 Blake2s-256 without Personalisation (Prefix DST)

Used for nonce derivation (Section 8.3), credential prehashing (Section 8.5 step 2), attestation messages (Section 10.2), and the RP hash second step (Section 13.2). This call pattern prepends the DST directly to the data.

**Reference library.** `blake2::Blake2s256` (Digest trait).

```
H_b2s(data):
    Blake2s256::new()
        .update(data)
        .finalize()                  // 32 bytes
```

When a DST is required, the caller prepends it to `data` before invoking `H_b2s`. There is no parameter block customisation.

The construction is plain Blake2s-256 as defined in [RFC7693] with no personalisation.

### 7.3 Distinction Between Personalisation and Prefix

The Blake2s personalisation slot and a literal prefix produce different outputs even for the same DST byte string. Implementations MUST NOT substitute one for the other. The personalisation parameter is an 8 byte slot in the Blake2s parameter block; the prefix is the leading bytes of the message itself.

Section 5.1 marks each DST with which call pattern uses it. `PROVII_RJ_PERSONALIZATION` is the only DST used as a personalisation; all other DSTs are used as prefixes.

### 7.4 SHA-256

Used for off circuit operations: PKCE (Section 13.4), the rp_challenge first step (Section 13.2), and the origin hash (Section 13.3).

**Reference library.** `sha2::Sha256`.

```
H_sha256(data):
    Sha256::new()
        .update(data)
        .finalize()                  // 32 bytes
```

SHA-256 is specified in [FIPS180-4]. Implementations MUST use a constant time implementation if any of the inputs include secret material; see Section 17.5.

### 7.5 Zcash Sapling Pedersen Hash

Used for commitments (Section 9.1) and nullifiers (Section 9.4). This is the windowed Pedersen hash from Zcash Sapling with fixed generator tables.

**Reference library.** `sapling_crypto::pedersen_hash::pedersen_hash`.

```
H_ped(personalization, bits):
    pedersen_hash(personalization, bits.into_iter())
        .into_subgroup()             // returns SubgroupPoint
```

The output is a Jubjub prime order subgroup point. Compression to 32 bytes is via the canonical Edwards form encoding. The generator points are deterministically derived from the personalisation tag per the Zcash Sapling specification, Section 5.4.1.7.

The personalisation is the 6 byte tag listed in Section 5.2. The bit vector is consumed in 3 bit windows per generator, with up to 63 windows per generator. Section 9.1 discusses the resulting input bit capacity.

### 7.6 Engineering Rationale

Blake2s-256 is used inside the circuit because its 32 bit additions, XORs, and rotations map to a small constant number of R1CS constraints per round. SHA-256 would require at least an order of magnitude more constraints. Pedersen hashing is used for the commitment because its discrete logarithm based hiding is constraint efficient and cleanly composes with the in circuit Jubjub arithmetic.

SHA-256 is used off circuit where R1CS efficiency is irrelevant and where compatibility with widely deployed primitives (PKCE, JWT-like constructions) is desirable.

---

## 8. RedJubjub Signature Scheme

This section specifies the custom RedJubjub instantiation used by Provii to sign credentials. The construction is **not** Zcash compatible. See Appendix E for explicit differences.

### 8.1 Key Generation

```
KeyGen():
    sk <- random element of Fr_J via CSPRNG
    if sk == 0: reject and resample
    VK <- [sk] G                         // G as in Section 4.3
    return (sk, VK)

Encoding:
    sk_bytes = sk.to_bytes()             // 32 bytes, canonical little endian
    vk_bytes = compress(VK)              // 32 bytes, compressed Edwards
```

Implementations MUST sample `sk` from a cryptographically secure pseudorandom number generator. Implementations MUST reject the zero scalar (which would produce `VK = identity`). Implementations MUST reject any `sk` outside the canonical range of `Fr_J`.

**Validation on deserialisation:**
- `SigningKey::from_bytes(sk_bytes)` MUST reject non canonical encodings without branching on the secret, and MUST reject the all zero encoding.
- `VerificationKey::from_bytes(vk_bytes)` MUST reject any input that does not decode to a Jubjub prime order subgroup point. Specifically, the small order subgroup MUST be rejected.

Source citation: `provii-crypto/crypto-sig-redjubjub/src/lib.rs:97-105`, `lib.rs:181-187`.

### 8.2 Credential Prehash

Before a credential is signed, its fields are serialised into a canonical byte string referred to as the credential prehash. The prehash format is a length prefixed concatenation, with explicit endianness for integer fields. The prehash includes the `CRED_DST` as its first 14 bytes; no further DST is required when hashing the prehash for signing.

```
CredPrehash(v, kid, c, iat, exp, schema):
    kid_b = kid.as_bytes()                // UTF-8
    sch_b = schema.as_bytes()             // UTF-8
    require len(kid_b) <= 255 (else FieldTooLong)
    require len(sch_b) <= 255 (else FieldTooLong)
    return CRED_DST                    // "provii.cred.v0", 14 bytes
        || u8(v)                          // 1 byte, version
        || u8(len(kid_b))                 // 1 byte, kid length prefix
        || kid_b                          // variable
        || c                              // 32 bytes, Pedersen commitment
        || BE(iat, 8)                     // 8 bytes, big endian
        || BE(exp, 8)                     // 8 bytes, big endian
        || u8(len(sch_b))                 // 1 byte, schema length prefix
        || sch_b                          // variable
```

The off circuit prehash format accepts variable length `kid` and `schema`. The age verification circuit (Section 12) requires `len(kid_b) == 14` and `len(sch_b) == 12` exactly. Therefore implementations MUST only sign credentials with `len(kid) == 14` and `len(schema) == 12` if those credentials are intended to be used as inputs to the age verification circuit. Off circuit only uses MAY use other lengths but lose circuit compatibility.

Issuer binding note. The prehash deliberately does not include `issuer_id`. A credential is bound to a particular issuer through two mechanisms that sit outside the signed byte string: (a) the RedJubjub verifying key used to check the signature, which the Wallet resolves through its local issuer registry (Section 11.8) and the Verifier resolves through its own issuer registry (Section 14.6 step 10f), and (b) the `kid` field inside the prehash, which identifies a specific key epoch within that issuer's keyset. Implementations MUST NOT treat `kid` alone as an issuer identifier; `kid` is only meaningful after an `issuer_vk` has been identified via registry lookup. A credential whose signature verifies under an unknown or unrelated `issuer_vk` MUST be rejected even if its `kid` collides with a known entry.

Source citation: `provii-crypto/crypto-commons/src/lib.rs:131`.

### 8.3 Nonce Derivation

The signature nonce is derived deterministically from the signing key and the message hash using a Blake2s-256 prefix construction. This eliminates the failure mode of weak random nonces (cf. ECDSA in non IETF deployments).

```
NonceDerive(sk_bytes, msg_hash):
    digest = H_b2s(PROVII_RJ_NONCE_TAG || sk_bytes || msg_hash)
                                          // PROVII_RJ_NONCE_TAG = "ProviiRJ/nonce", 14 bytes
                                          // sk_bytes: 32 bytes
                                          // msg_hash: 32 bytes
                                          // Total input: 78 bytes; output: 32 bytes
    wide  = digest || 0x00^32             // pad to 64 bytes
    return wide_reduce_J(wide)            // reduce into Fr_J via from_bytes_wide
```

The 32 byte Blake2s output is placed into bytes 0..32 of a 64 byte buffer; bytes 32..64 are zero. The 64 byte buffer is then reduced to an element of `Fr_J` via the standard `from_bytes_wide` two block reduction.

This is conceptually similar to [RFC6979] (deterministic ECDSA) but uses Blake2s-256 in place of HMAC and operates directly over `Fr_J`.

Source citation: `provii-crypto/crypto-sig-redjubjub/src/lib.rs:229-246`.

### 8.4 Challenge Hash

The signature challenge `c` is computed via Blake2s-256 with the `PROVII_RJ_PERSONALIZATION` personalisation tag:

```
ChallengeHash(R_bytes, VK_bytes, msg_hash):
    digest = H_b2s(PROVII_RJ_PERSONALIZATION,
                   R_bytes || VK_bytes || msg_hash)
                                          // PROVII_RJ_PERSONALIZATION = "ProviiRJ", 8 bytes (in personal slot)
                                          // R_bytes: 32 bytes
                                          // VK_bytes: 32 bytes
                                          // msg_hash: 32 bytes
                                          // Total input: 96 bytes; output: 32 bytes
    wide   = digest || 0x00^32            // pad to 64 bytes
    return wide_reduce_J(wide)            // reduce into Fr_J
```

**CRITICAL.** The personalisation parameter `PROVII_RJ_PERSONALIZATION` is set on the Blake2s parameter block via `Params::personal()`. It is NOT prepended to the data. Compare with Section 8.3, which prepends `PROVII_RJ_NONCE_TAG` to the data and uses no personalisation. Confusing the two yields different `c` values and produces signatures that do not verify.

Source citation: `provii-crypto/crypto-sig-redjubjub/src/lib.rs:250-271`.

### 8.5 Sign

```
Sign(sk, cred):
    prehash  = CredPrehash(cred.v, cred.kid, cred.c, cred.iat, cred.exp, cred.schema)
    msg_hash = H_b2s(prehash)             // Blake2s-256, no personalisation. 32 bytes.
    nonce    = NonceDerive(sk_bytes, msg_hash)
    R        = [nonce] G
    VK       = [sk] G
    c        = ChallengeHash(compress(R), compress(VK), msg_hash)
    s        = nonce + c * sk             // in Fr_J
    return (R, s)

Encoding:
    signature = compress(R) || s.to_bytes()
                                          // 32 + 32 = 64 bytes
```

The Issuer MUST verify the signature it has just produced (see Section 11.4 Step 8) as a self check before returning the SignedCredential to the Wallet. This catches misconfigured CSPRNGs, key corruption, and library version skew at issuance time rather than at verification time.

Source citation: `provii-crypto/crypto-sig-redjubjub/src/lib.rs:277-412`.

### 8.6 Verify

```
Verify(VK, cred, sig):
    parse R from sig[0..32]
    parse s from sig[32..64]
    require R is canonical and in the prime order subgroup
    require s is canonical in Fr_J
    if any of the above fails, return false without further computation

    prehash  = CredPrehash(cred.v, cred.kid, cred.c, cred.iat, cred.exp, cred.schema)
    msg_hash = H_b2s(prehash)
    c        = ChallengeHash(compress(R), compress(VK), msg_hash)
    LHS      = [s] G
    RHS      = R + [c] VK
    return LHS == RHS                     // u/v coordinate equality
```

Implementations MUST check `R` and `s` for canonicality before the algebraic check. The point comparison MUST use constant-time primitives (e.g. `subtle::ConstantTimeEq`) even though neither operand is secret, to avoid leaking which intermediate check failed during non-conforming input handling. Failure modes (non canonical, identity, small subgroup, point equality false) MUST all return the same `false` result without leaking which check failed.

Source citation: `provii-crypto/crypto-sig-redjubjub/src/lib.rs:332-357`.

### 8.7 Determinism

The nonce derivation in Section 8.3 is a pure function of `sk_bytes` and `msg_hash`. Therefore RedJubjub signatures in Provii are fully deterministic: signing the same credential under the same key always produces the same 64 byte signature. Conforming implementations MUST reproduce signature bytes byte for byte across implementations given identical inputs. Test vectors in Appendix A pin canonical inputs and expected outputs.

### 8.8 Key Zeroisation

Implementations MUST zeroise secret key material on drop or scope exit using volatile writes that the compiler cannot elide. Rust implementations MUST use the `zeroize` crate or equivalent. Where the underlying scalar type does not implement `Zeroize` directly (the upstream `jubjub` crate at the time of writing does not), implementations MUST overwrite the scalar bytes via a documented `unsafe` block whose safety invariant is reviewed.

Implementations MUST NOT log, debug print, or serialise secret keys outside of secure storage.

---

## 9. Pedersen Commitment Scheme

### 9.1 Commitment

The Pedersen commitment [Pedersen1991] hides a date of birth using the Sapling Pedersen hash with the `NoteCommitment` personalisation.

```
PedersenCommit(dob_days, r_bits):
    biased   = bias_for_circuit(dob_days)         // u32, see Section 6.3
                                                  // = (dob_days as u32) XOR 0x8000_0000
    dob_bits = bits_le(biased, 32)                // 32 bits, byte-LE then bit-LE
    input    = dob_bits || r_bits                 // 32 + len(r_bits) bits
    point    = H_ped(NoteCommitment, input)       // Sapling Pedersen hash
    return compress(point)                        // 32 bytes
```

**Parameters:**
- `dob_days`: `i32` representing days since the Unix epoch, signed to support pre-1970 dates.
- `r_bits`: random bit vector. The circuit (Section 12) requires exactly 128 bits. Off circuit code MAY accept up to 1096 bits but only credentials with 128 bit randomness are circuit compatible.
- Output: 32 byte compressed Jubjub point.

**Capacity limit.** The Sapling Pedersen hash provides 6 generators, each consuming up to 63 windows of 3 bits, for a total of 1134 input bits. The 6 bit personalisation slot consumes 6 bits, leaving 1128 for the user payload. After 32 bits for `dob_days`, at most 1096 bits of randomness can be accepted. Inputs exceeding this limit MUST be rejected at the validation boundary; the underlying Sapling implementation returns the identity point in that case, but Provii implementations MUST reject before that point.

**Properties:**
- *Perfectly hiding.* For any commitment `C` and any candidate `dob_days` `m`, there exists `r` such that `PedersenCommit(m, r) = C`. The commitment reveals no information about the committed value.
- *Computationally binding.* Under the discrete log assumption on Jubjub, an adversary cannot find two distinct openings `(m1, r1) != (m2, r2)` with `PedersenCommit(m1, r1) == PedersenCommit(m2, r2)`.

The construction is also circuit compatible: the off circuit code matches the in-circuit Pedersen commitment gadget bit for bit, so any commitment produced off circuit will open correctly inside the age circuit of Section 12.

### 9.2 Bias of the Date of Birth

The bias step (Section 6.3) maps the signed `dob_days` to an unsigned `u32` whose ordering preserves the signed ordering. This is required for the in circuit comparison (Section 12.7 step 5) to operate over unsigned integers, which is significantly cheaper than signed comparison in R1CS.

For example, `bias(-3653) = 2147479995`, `bias(0) = 2147483648 = 0x80000000`, and `bias(13880) = 2147497528`. The unsigned ordering of these biased values matches the signed ordering of the original values. See Appendix A.1 for additional worked values.

### 9.3 Entropy Validation

Before computing a commitment, randomness MUST be validated to defend against accidental supply of weak randomness. The validation rules are defence in depth measures, not cryptographic requirements; a properly seeded CSPRNG satisfies them with overwhelming probability.

Two validation profiles apply depending on the caller.

#### 9.3.1 Profile A (Circuit Path, Wallet, and Issuer)

Any `r_bits` fed into `pedersen_commit_dob` or any other value that will be consumed by the v0.1 age circuit MUST satisfy `len(r_bits) == R_BITS_LEN` (128 bits). This is a hard equality: the circuit only accepts exactly 128 bits of randomness (the named constant lives at `provii-mobile-sdk/crates/core/src/issuance.rs:24`; the prover and the circuit perform independent hard-coded `128` length checks at `provii-crypto/crypto-prover/src/lib.rs:1491` and `provii-crypto/crypto-circuit-age/src/lib.rs:306` respectively). Inputs that do not match MUST be rejected and MUST NOT be truncated or padded.

#### 9.3.2 Profile B (Standalone Commitment Helper)

The general purpose `validate_commitment_randomness` helper (exposed for uses outside the v0.1 age circuit, for instance test tooling or future circuits that accept longer randomness) enforces a lower bound of `MIN_PEDERSEN_RANDOMNESS_BITS` (≥ 128 bits) and an upper bound of `MAX_PEDERSEN_RANDOMNESS_BITS` (1096 bits). Lengths below 128 bits MUST be rejected. Lengths above 1096 bits MUST be rejected.

In both profiles:

```
ValidateRandomness(r_bits):
    require MIN_PEDERSEN_RANDOMNESS_BITS <= len(r_bits) <= MAX_PEDERSEN_RANDOMNESS_BITS
                                          // 128 <= len(r_bits) <= 1096 (Profile B)
                                          // 128 == len(r_bits)         (Profile A)
    require r_bits is not all zero
    bytes  = pack_bits_to_bytes(r_bits)
    unique = count distinct byte values in bytes
    require unique >= MIN_UNIQUE_BYTES_R_BITS
                                          // >= 8
```

A conforming Wallet MUST apply Profile A before computing a commitment that will be consumed by the v0.1 age circuit. A conforming Issuer MUST apply Profile A on the `r_bits` it receives from a Wallet before using them to compute a circuit-consumable commitment.

Inputs that fail validation MUST be rejected with an `InvalidInput` error. Implementations MUST NOT silently substitute a different value for the supplied randomness, and MUST NOT truncate or pad randomness to satisfy a length check.

Source citation: `provii-crypto/crypto-commit/src/lib.rs:192` (Profile B entropy validation) and `provii-crypto/crypto-commit/src/lib.rs:229` (literal `>= 8` unique-byte check); `provii-mobile-sdk/crates/core/src/issuance.rs:24` (`R_BITS_LEN` named constant), `provii-crypto/crypto-prover/src/lib.rs:1491` and `provii-crypto/crypto-circuit-age/src/lib.rs:306` (Profile A length checks).

### 9.4 Nullifier

The nullifier is a deterministic 32 byte value derived from the commitment using a second Pedersen hash with a distinct personalisation (`MerkleTree(0)`) and a distinct DST embedded as bit input (`NULLIFIER_DST`).

```
PedersenNullifier(c_bytes):
    DST_bits = bits_le(NULLIFIER_DST, 28*8)   // 224 bits, byte-LE then bit-LE
    c_bits   = bits_le(c_bytes, 32*8)         // 256 bits, same convention
    input    = DST_bits || c_bits             // 480 bits
    point    = H_ped(MerkleTree(0), input)
    return compress(point)                    // 32 bytes
```

**Determinism.** For a given commitment, the nullifier is deterministic. Two proofs generated from the same credential present the same nullifier. Verifiers use this property to maintain a ban store of nullifiers belonging to abusive or compromised credentials; any proof whose nullifier is in the ban store is rejected. Replay protection is handled separately by single-use challenge consumption, the `submit_secret`, and PKCE.

**Determinism at the Verifier.** The nullifier is the same 32 bytes for any proof generated from a given Credential. This property is what lets the Verifier maintain a nullifier ban store (Section 14.9) and is scoped to the single Provii-operated Verifier.

**Domain separation construction.** The DST is included as a *bit level input* to the Pedersen hash, not as the personalisation parameter. The personalisation is `MerkleTree(0)` (the six bit prefix `000000`, see Section 5.2), while the DST `provii.nullifier.pedersen.v0` flows in as the leading 224 bits of the input. This is a deliberate construction: the personalisation slot is reserved to distinguish nullifier from commitment Pedersen hashes; the DST adds protocol level separation from any other use of `MerkleTree(0)`.

Source citation: `provii-crypto/crypto-commit/src/lib.rs:123-149`.

### 9.5 Subgroup Check on Deserialised Commitments

Implementations that deserialise a commitment from a wire encoding (for example, from a stored credential) MUST check that the 32 byte input decodes to a point in the Jubjub prime order subgroup. A point that fails subgroup check MUST be rejected as an invalid commitment.

---

## 10. Ed25519 Attestation Scheme

The Ed25519 attestation is a signed statement produced by the Issuer in response to an authenticated request from an Issuing Party. It asserts that the Issuing Party has verified (through its own IdP and KYC systems) that the named subject has a particular date of birth, and it binds that assertion to a short freshness window. The attestation is the sole mechanism by which the Wallet presents a trusted `dob_days` to the Issuer during blind issuance.

### 10.1 Signer

Provii defines a single signer for Ed25519 attestations: the Issuer. The Issuer holds the Ed25519 signing key under KEK-encrypted storage and responds to authenticated Issuing Party requests at its attestation creation endpoint (Section 11). No other party signs attestations; the IdP holds no Ed25519 key and is never a signer for the purposes of this specification.

The Issuer's Ed25519 verifying key is retained internally and used by the Issuer's own verification step (Section 10.4) when the Wallet presents an attestation back during blind issuance. The Verifier does not consult Ed25519 verifying keys; it consults RedJubjub verifying keys only.

### 10.2 Attestation Message Construction

```
AttestationMessage(dob_days, issuer_id, timestamp, nonce,
                   session_id, client_id):
    issuer_b  = issuer_id.as_bytes()              // UTF-8
    session_b = session_id.as_bytes()             // UTF-8
    client_b  = client_id.as_bytes()              // UTF-8
    require len(issuer_b)  <= 255 (else FieldTooLong)
    require len(session_b) <= 255 (else FieldTooLong)
    require len(client_b)  <= 255 (else FieldTooLong)
    require len(nonce) == 32

    return H_b2s(
        DOB_ATTESTATION_DST                       // "provii.attestation.dob.v0", 25 bytes
        || LE(dob_days, 4)                        // 4 bytes, signed i32 little endian
        || u8(len(issuer_b))                      // 1 byte, length prefix
        || issuer_b                               // variable, UTF-8
        || LE(timestamp, 8)                       // 8 bytes, unsigned u64 little endian
        || nonce                                  // 32 bytes
        || u8(len(session_b))                     // 1 byte, length prefix
        || session_b                              // variable, UTF-8
        || u8(len(client_b))                      // 1 byte, length prefix
        || client_b                               // variable, UTF-8
    )
                                                  // 32 bytes (Blake2s-256 digest)
```

The attestation uses **little endian** for `dob_days` and `timestamp`, in contrast with the credential prehash (Section 8.2) which uses big endian for `iat` and `exp`. This is deliberate and reflects the historical division between attestation level and credential level encoding.

`session_id` binds the attestation to the Issuing Party's session with the Issuer. `client_id` identifies the Issuing Party's registered `CLIENT_ID` at the Issuer. Both fields are covered by the signature; substituting either after signing produces a verification failure. Wallets relay the attestation verbatim; they do not generate or mutate these fields.

**`dob_days` sanity range.** The Issuer constructing an attestation and the Issuer verifying a received attestation MUST reject any attestation whose `dob_days` falls outside the inclusive range `[-36525, +36525]`. This bounds the plausible date of birth to approximately ±100 years from the Unix epoch (1970-01-01 UTC), which encompasses every age verification use case (including issuance for infants) while rejecting obvious garbage or malicious wrapping toward `i32::MIN` or `i32::MAX`.

Source citation: `provii-crypto/crypto-commons/src/attestation.rs`, `AttestationMessage::canonical_bytes`.

### 10.3 Create Attestation

```
CreateAttestation(dob_days, issuer_id, timestamp, nonce,
                  session_id, client_id, ed25519_sk):
    msg = AttestationMessage(dob_days, issuer_id, timestamp, nonce,
                             session_id, client_id)
    sig = Ed25519.Sign(ed25519_sk, msg)           // 64 bytes
    return Attestation {
        dob_days,
        issuer_id,
        timestamp,
        nonce,
        session_id,
        client_id,
        signature: sig,
    }
```

The signing key `ed25519_sk` MUST be 32 bytes and MUST be sourced from a CSPRNG. The signing key MUST be zeroised on drop and MUST reside under the Issuer's KEK-encrypted key store.

### 10.4 Verify Attestation

```
VerifyAttestation(attestation, ed25519_vk):
    msg = AttestationMessage(
        attestation.dob_days,
        attestation.issuer_id,
        attestation.timestamp,
        attestation.nonce,
        attestation.session_id,
        attestation.client_id,
    )
    return Ed25519.Verify(ed25519_vk, msg, attestation.signature)
```

The verification step MUST use a strict verification implementation that rejects malleable signatures, per [RFC8032] Section 5.1.7.

### 10.5 Verify with Freshness

```
VerifyAttestationFresh(attestation, ed25519_vk, current_time):
    require -36525 <= attestation.dob_days <= 36525                                 // sanity
    require current_time - attestation.timestamp <= ATTESTATION_MAX_AGE_SECONDS    // 3600
    require attestation.timestamp - current_time <= ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS // 60
    require VerifyAttestation(attestation, ed25519_vk) succeeds
```

A conforming Issuer MUST reject any attestation with `dob_days` outside `[-36525, +36525]` (Section 10.2). A conforming Issuer MUST reject attestations whose timestamp is more than `ATTESTATION_MAX_AGE_SECONDS` (3600) seconds older than its local current time. A conforming Issuer MUST reject attestations whose timestamp is more than `ATTESTATION_CLOCK_SKEW_TOLERANCE_SECONDS` (60) seconds ahead of its local current time. The future skew bound is tighter than the past bound because attestations far in the future indicate clock attack rather than ordinary clock drift. The freshness past bound is shorter than the nonce single-use window (`ATTESTATION_NONCE_TTL_SECONDS`). This guarantees that if a nonce was consumed (recorded in the consumed-nonce store) during the freshness window, its entry is still retained when any replay arrives, preventing boundary replays (replay attempts timed to fall between the freshness window expiry and the nonce store TTL expiry). An attacker who delays a captured attestation beyond `ATTESTATION_MAX_AGE_SECONDS` fails the freshness check; one who replays it within `ATTESTATION_MAX_AGE_SECONDS` is caught by the nonce store, which retains consumed entries for the full `ATTESTATION_NONCE_TTL_SECONDS` TTL.

Source citation: `provii-crypto/crypto-commons/src/attestation.rs`, `Attestation::verify_with_timestamp`.

### 10.6 Nonce Single Use

A conforming Issuer MUST track attestation nonces and reject any nonce it has already accepted within the freshness window. The nonce is 32 bytes from a CSPRNG, so collisions are negligible; any apparent reuse is treated as a replay attempt.

The nonce store MUST retain each consumed nonce for at least `ATTESTATION_NONCE_TTL_SECONDS` (7200 seconds) from the time of consumption. Retention beyond `ATTESTATION_NONCE_TTL_SECONDS` from the time of consumption is optional. Entries MAY be evicted after that deadline.

Normatively, the single-use guarantee requires an atomic check-and-set on the nonce store: concurrent requests presenting the same nonce MUST NOT both succeed. Eventually-consistent stores that permit a TOCTOU window between read and write MUST NOT be used for this purpose unless an independent single-writer coordinator is interposed.

Note (informative). The reference `provii-issuer` implementation satisfies the atomic check-and-set requirement via a Cloudflare Durable Object keyed on the prefixed nonce string (`attest:<nonce_hex>`), with TTL-based eviction at `ATTESTATION_NONCE_TTL_SECONDS` (7200 seconds). See `provii-issuer/src/storage.rs::validate_and_consume_attestation_nonce` and `provii-issuer/src/durable_objects/nonce_do.rs::check_and_set_internal`. Other Issuer implementations are free to choose any backing store that provides equivalent single-writer atomicity; the Durable Object choice is not normative.

### 10.7 Field Length Validation

The attestation construction enforces the following length bounds. Implementations MUST raise `FieldTooLong` (or equivalent) for inputs exceeding these bounds.

| Field | Constraint |
|---|---|
| `issuer_id` | byte length ≤ 255 |
| `session_id` | byte length ≤ 255 |
| `client_id` | byte length ≤ 255 |
| `nonce` | byte length == 32 |

`dob_days`, `timestamp`, and `signature` are fixed length and bound by their type encoding.

### 10.8 Memory Hygiene

The `Attestation` and `AttestationKey` (or equivalent) types MUST be `Zeroize + ZeroizeOnDrop`. Their `Debug` implementations MUST NOT print secret material; the conforming behaviour is to print the literal `[REDACTED]` for secret fields.

---

## 11. Issuance Protocol

This section specifies the full issuance flow as a numbered sequence of normative steps. Issuance is split into three hops: Issuing Party to Issuer (attestation creation), Issuing Party to Wallet via platform deep link (attestation delivery), and Wallet to Issuer (blind credential issuance).

### 11.1 Preconditions

Before issuance can begin, the following preconditions MUST hold.

1. The Issuer has provisioned a 32 byte Ed25519 attestation signing key in KEK-encrypted storage. Its corresponding verifying key is retained for the Issuer's own verification step in Section 10.
2. The Issuer has provisioned a RedJubjub credential signing key (`SigningKey`, 32 bytes) and a corresponding `VerificationKey` (32 bytes). The `VerificationKey` is published to the Verifier's issuer registry.
3. The Issuing Party has been provisioned at the Issuer with a `CLIENT_ID` and an HMAC-SHA256 client secret, and holds those credentials in its own secure storage.
4. The Issuing Party has authenticated the user via its own IdP and has resolved a verified `dob_days` from its KYC record.

### 11.2 Issuing Party to Issuer: Attestation Creation

**Request.** The Issuing Party sends a POST to the Issuer's attestation creation endpoint (`/v0/attestation/create`) over TLS with the following HMAC-SHA256 authentication headers:

| Header | Value |
|---|---|
| `X-Client-Id` | The Issuing Party's registered `CLIENT_ID` |
| `X-Timestamp` | Unix seconds at request formation |
| `X-Signature` | base64url(HMAC-SHA256(client_secret, CanonicalRequest)) |

Where `CanonicalRequest = {X-Timestamp} || ":" || "POST" || ":" || "/v0/attestation/create" || ":" || hex(dob_days_le) || authorizer_json`. `authorizer_json` identifies the registered Issuing Party session; see the reference implementation for the canonical JSON shape.

The request body carries `dob_days` (signed i32), an optional `session_id`, and an optional `client_id` (when different from the authenticating `X-Client-Id`, for delegated issuance). Implementations MAY support an `X-Api-Key` fast-path for low-volume integrators; the HMAC-SHA256 path is normative.

**Child-DOB guard.** The Issuer MUST reject any attestation creation request where the resulting age at request time is less than 6574 days (approximately 18 years). This guard protects against mass enrolment of minors through generic client integrations; Issuing Parties with legitimate under-18 issuance needs (government agencies, regulated youth services) MUST obtain a separately-provisioned `CLIENT_ID` flagged for under-18 issuance. Requests from non-flagged clients that would produce an attestation for a minor MUST be rejected with a dedicated error code.

**Constant-time authentication check.** The Issuer MUST compare the received HMAC-SHA256 signature against the computed signature using `hmac::Mac::verify_slice` or an equivalent platform primitive (Section 17.5). String comparison is prohibited.

**Issuer response.** On success, the Issuer:

1. Generates a 32 byte nonce from its CSPRNG.
2. Constructs the attestation message per Section 10.2 over `dob_days`, its configured `issuer_id`, the current Unix timestamp, the nonce, the resolved `session_id`, and the resolved `client_id`.
3. Signs the message with its Ed25519 signing key (Section 10.3). The nonce is not recorded at this point. It is consumed later, at blind-issuance time (Section 11.4, Step 4), when the Wallet presents the attestation. The Issuer's nonce store holds already-consumed nonces and rejects any nonce that is already present, enforcing single-use semantics (Section 10.6).
4. Returns the resulting `Attestation` to the Issuing Party.

**Error handling.** HMAC verification failures, child-DOB guard triggers, malformed bodies, and replayed timestamps (outside the server's skew tolerance) MUST be reported to the Issuing Party with distinct error codes. The Issuer MUST NOT disclose which sub-check failed beyond the minimum necessary for the Issuing Party to correct its request.

### 11.3 Issuing Party to Wallet: Attestation Delivery

The Issuing Party MUST deliver the attestation to the Wallet via a platform deep link. The deep-link URL scheme and parameter layout are outside the scope of this specification; the reference implementation in `provii-mobile` accepts a canonical deep link that embeds the attestation as a base64url value along with the Issuing Party's display name. Implementations MAY use QR codes for desktop-initiated issuance, in which case the QR payload MUST carry the same fields as the deep link.

The Issuing Party MUST NOT store the attestation beyond the call stack needed to construct the deep link. Retention of the attestation past the deep-link handoff creates a replay surface that the nonce single-use check can only partially mitigate.

### 11.4 Wallet to Issuer: Blind Credential Issuance

```
Step 1.  The Wallet receives the deep link and parses the attestation.
         The Wallet MAY verify the attestation's Ed25519 signature
         against the Issuer's published verifying key at this point;
         verification is not normative here because the Issuer will
         verify its own signature in Step 4, but early verification
         surfaces corruption quickly.

Step 2.  The Wallet generates 128 bits of commitment randomness from
         the platform CSPRNG. The Wallet calls ValidateRandomness on
         the result; if validation fails, it generates a new value.

         Source: OsRng on native, getrandom (Web Crypto API) on WASM.

Step 3.  The Wallet sends a POST to the Issuer's blind-issuance
         endpoint (`/v0/issuance/blind`) over TLS with a JSON body:

            {
              "attestation": <base64url Attestation wire bytes>,
              "r_bits":      <base64url 16 bytes (128 bits)>
            }

Step 4.  The Issuer verifies the Attestation:
            - issuer_id matches the Issuer's configured identity
            - Ed25519 signature valid (Section 10.4)
            - timestamp within freshness bounds (Section 10.5)
            - nonce not previously consumed (Section 10.6)
            - dob_days within [-36525, +36525]

         If any check fails, the Issuer MUST reject and MUST NOT
         proceed with issuance. On success, the nonce MUST be
         atomically recorded in the consumed-nonce store with TTL
         ATTESTATION_NONCE_TTL_SECONDS (7200 seconds) per
         Section 10.6.

Step 5.  The Issuer validates r_bits via ValidateRandomness
         (Section 9.3). On failure, it MUST reject.

Step 6.  The Issuer computes the commitment server side:
            c = PedersenCommit(attestation.dob_days, r_bits)
         The commitment is 32 bytes.

Step 7.  The Issuer constructs CredMsgV2:
            v       = 2
            kid     = the Issuer's current key identifier (UTF-8,
                      exactly 14 bytes; required for circuit
                      compatibility, see Section 12.4)
            c       = from Step 6
            iat     = current Unix seconds
            exp     = iat + the credential validity period
            schema  = the credential schema identifier (UTF-8,
                      exactly 12 bytes, e.g. "provii.age/0";
                      required for circuit compatibility,
                      see Section 12.4)

         The Issuer MUST enforce the `kid` and `schema` length
         constraints at attestation dispatch. A credential with a
         non-conforming `kid` or `schema` cannot be proved against the
         Groth16 circuit and constitutes a protocol error.

         The Issuer MUST set `iat` within
         `CLOCK_SKEW_TOLERANCE_SECONDS` of its wall-clock current
         time. The Issuer MUST set `exp > iat` and
         `exp - iat <= MAX_VALIDITY_SECONDS` (3 153 600 000;
         36 500 days, ~100 years). The RECOMMENDED default for
         general deployments is 7 300 days (20 years) so the
         credential ages with the user; see Section 17.12 for the
         operator tradeoffs around shorter or longer values.

         The Issuer computes the credential prehash (Section 8.2),
         Blake2s hashes it, and signs the hash via RedJubjub
         (Section 8.5) using its credential signing key.

Step 8.  The Issuer self verifies the signature (Section 8.6). If
         self verification fails, the Issuer MUST abort and MUST NOT
         return the credential. Self verification catches
         misconfigured CSPRNGs, key corruption, and library drift.

Step 9.  The Issuer returns the SignedCredential to the Wallet:
            SignedCredential {
                v, kid, c_bytes, iat, exp, schema,
                issuer_vk: bytes(VerificationKey),
                sig_rj:    64 bytes from Step 7,
            }

Step 10. The Issuer discards dob_days and r_bits from memory
         (zeroise). The Issuer records audit metadata as specified in
         Section 11.6 but MUST NOT retain dob_days or r_bits.

Step 11. The Wallet MUST verify the received credential before
         persisting it:
            a. Recompute c' = PedersenCommit(attestation.dob_days,
               stored r_bits) and confirm c' == credential.c_bytes
               in constant time.
            b. If the Wallet maintains an issuer registry (Section
               11.7), resolve issuer_vk through it using
               (issuer_id, kid). Reject if the pair is explicitly
               marked Revoked.
            c. Verify the RedJubjub signature on the credential
               prehash (Section 8.6). Where a registry is present
               the signature MUST be verified against the
               registry-resolved verifying key. Where v0.1 wallets
               operate without a registry (Section 11.7), the
               signature is verified against the verifying key
               transmitted in the credential header.
            d. Confirm iat <= current_time < exp.
         If any check fails, the Wallet MUST discard the credential
         and MUST NOT persist any part of it to platform secure
         storage.

Step 12. The Wallet stores the SignedCredential, the attestation's
         dob_days, and the r_bits in platform secure storage (iOS
         Keychain, Android Keystore, or equivalent).
```

### 11.5 Officer Attestation Variant

The Issuer MAY expose an officer attestation path that substitutes a YubiKey HMAC-SHA1 challenge/response for the HMAC-SHA256 client authentication in Section 11.2. This path is intended for human operator flows (for example, government counter staff enrolling citizens). The officer attestation path still invokes the same `CreateAttestation` routine (Section 10.3) and produces attestations indistinguishable from Section 11.2 attestations on the wire. Officer attestation provisioning, YubiKey binding, and access-control policy are outside the scope of this specification.

### 11.6 Audit Log Retention at Issuance

The Issuer MUST NOT retain `dob_days`, `r_bits`, the commitment, or the attestation nonce beyond the operational windows defined in Sections 10.6 and 11.4. The Issuer MAY retain audit metadata sufficient to demonstrate that issuance occurred:

| Field | Purpose |
|---|---|
| Event type (e.g. `IssuanceCompleted`) | Audit category |
| Timestamp | When issuance occurred |
| Issuing Party identifier (`client_id`) | Which Issuing Party requested the attestation |
| Issuing Party display name | Human readable |
| `kid` | Which credential signing key was used |
| Validity period (`iat`, `exp`) | When the credential expires |
| Schema identifier | Credential schema |

Audit log retention MUST NOT exceed 90 days after issuance unless a longer period is required by applicable regulation. Audit log entries MUST NOT enable reconstruction of the user's date of birth.

### 11.7 Wallet Storage

The Wallet MUST store the SignedCredential, `dob_days`, and `r_bits` in platform secure storage. On iOS the platform secure storage is the Keychain with appropriate accessibility flags. On Android the platform secure storage is the Keystore. Implementations on other platforms MUST use an equivalent mechanism that protects the data at rest with hardware backing where available.

The Wallet MUST NOT export `dob_days` or `r_bits` over any application boundary except the proof generation path defined in Section 13.

### 11.8 Wallet Issuer Registry

A Wallet SHOULD maintain an issuer registry: a local, integrity-protected mapping from `issuer_id` (UTF-8) and `kid` (UTF-8) to the expected RedJubjub issuer verifying key. The registry serves two purposes: it lets the Wallet reject credentials signed by an unknown issuer at enrolment time, and it lets the Wallet reject an attempted substitution of `issuer_vk` on a stored credential.

Target requirements for a full registry implementation:

1. Before accepting a SignedCredential returned by the Issuer, the Wallet SHOULD verify that the credential's `(issuer_id, kid)` pair is present in the registry.
2. The Wallet SHOULD verify the RedJubjub signature on the credential against the registry-resolved verifying key, not against a key provided inline by the Issuer.
3. The Wallet SHOULD refuse to enrol with an issuer whose `(issuer_id, kid)` is not present in the registry. A Wallet MAY offer an explicit, user-mediated path to add a new issuer; that path SHOULD display the fingerprint of the new verifying key and require deliberate user confirmation before persisting.
4. Registry entries include a status field (`Active`, `Deprecated`, `Revoked`). An `Active` entry is eligible for new enrolments. A `Deprecated` entry is retained only so existing stored credentials continue to validate until they expire. A `Revoked` entry SHOULD cause the Wallet to reject every credential that references it, including credentials already stored.
5. Registry state SHOULD be stored inside the same platform secure storage boundary as `dob_days` and `r_bits` (Section 11.7). The registry SHOULD be integrity protected; a Wallet that cannot verify the registry's integrity on load SHOULD refuse to generate proofs until the registry is re-established through a trusted channel.
6. The Wallet SHOULD NOT silently adopt a verifying key shipped alongside a credential at enrolment or verification time. Any key rotation SHOULD flow through the registry update path.

The wallet issuer registry is independent of the Verifier's issuer registry (Section 2.2, Section 14.6 step 10f).

**Implementation status in v0.1.** The v0.1 reference provii-mobile-sdk does not yet implement a signed, integrity-protected issuer registry. Until it does, wallets accept the `issuer_vk` transmitted in the credential header after verifying the RedJubjub signature over the credential prehash. Deployments concerned about issuer key substitution SHOULD bundle a trusted issuer list with the wallet binary (an immutable asset shipped in the application bundle, verified at build time) until a runtime registry ships; a compile-time list provides a weaker form of the same guarantees without the runtime update path.

---

## 12. Age Verification Circuit

The age verification circuit proves, in zero knowledge, that the prover holds a validly-signed credential for a date of birth that satisfies an age threshold, without revealing the date of birth, the signature, or the commitment randomness.

### 12.1 Overview

The circuit is a single Groth16 R1CS over BLS12-381. It binds together three statements: (a) the prover holds an opening of the public commitment, (b) the commitment is signed by the public issuer verifying key under RedJubjub, (c) the date of birth in the opening satisfies the age predicate selected by the public direction bit and cutoff days. The circuit produces 8 declared public inputs which Bellman augments with an implicit `1` to produce an `ic.len() == 9` verifying key.

### 12.2 Direction Bit

The circuit supports two age comparison directions via a single Boolean public input.

| Direction | Bit value | Semantics | Constraint after conditional swap |
|---|---|---|---|
| Over | `1` (true) | User is at least the threshold age | `cutoff_days >= dob_days` |
| Under | `0` (false) | User is at most the threshold age | `dob_days >= cutoff_days` |

Boundary behaviour. Both inequalities are non-strict (`>=`, not `>`). The boundary case `cutoff_days == dob_days` therefore satisfies both directions: a user born on exactly the cutoff date passes an `Over` check, and equivalently passes an `Under` check at the same cutoff. Relying Parties that require strict-greater semantics MUST adjust their chosen `cutoff_days` by one day rather than request a strict comparison from the protocol; v0.1 does not expose a strict-inequality mode.

Both directions share a single R1CS and therefore share a single trusted setup, single proving key, single verifying key, and single `vk_id`. A conditional swap (multiplexer) gadget selects the operand order at proving time based on the direction input. The cost is 4 R1CS multiplication constraints per bit (two per operand, because both `left` and `right` are computed from an identical multiplexer expression), totalling 128 constraints for the 32 bit comparison, which is negligible compared to the in circuit Blake2s and Pedersen costs.

The unification was a deliberate design choice. An earlier draft had two circuits (one for Over, one for Under) requiring two trusted setups, two proving keys, two verifying keys, and double the registry maintenance. Routing direction through a public input collapses this to a single setup at modest cost.

### 12.3 Public Inputs

The circuit exposes 8 BLS12-381 scalar field elements (`Fr_B`), packed via Zcash's multipack algorithm.

| Index | Source | Bits | Field elements | Encoding |
|---|---|---|---|---|
| 0 | `direction` | 32 (LE bits of `direction as u32`, only bit 0 carries information) | 1 | LE bytes → LE bits |
| 1 | `bias_for_circuit(cutoff_days)` | 32 (LE bits of biased u32) | 1 | LE bytes → LE bits |
| 2-3 | `rp_hash` | 256 (32 bytes) | 2 | Raw byte order → LE bits within each byte |
| 4-5 | `issuer_vk_bytes` | 256 (32 bytes, raw VK) | 2 | Raw byte order → LE bits within each byte |
| 6-7 | `cred_nullifier` | 256 (32 bytes) | 2 | Raw byte order → LE bits within each byte |

Total: 1 + 1 + 2 + 2 + 2 = **8 declared public inputs**. With Bellman's implicit `1` at index 0, the verifying key has `ic.len() == 9`.

The packing order is: direction → cutoff → rp_hash → issuer_vk → nullifier. Implementations MUST pack public inputs in exactly this order. A mismatch between prover packing and verifier packing causes silent verification failure.

**Multipack chunking.** 256 bit values are split into chunks of at most 254 bits (BLS12-381 scalar capacity). A 256 bit value therefore requires exactly 2 field elements. The implementation includes an explicit bit 254 preservation step to ensure no bit is dropped during chunking. Implementations MUST preserve all bits of the source bytes; they MUST NOT mask or truncate.

### 12.4 Private Witness

| Field | Type | Size | Visibility | Notes |
|---|---|---|---|---|
| `dob_days` | `i32` | 32 bits (biased to u32 via `SIGN_BIAS`) | secret | Zeroised on drop |
| `r_bits` | `[bool]` | exactly 128 bits | secret | Zeroised on drop |
| `issuer_vk_bytes` | `[u8; 32]` | 256 bits | public (also a public input) | Skipped from zeroise |
| `sig_rj_bytes` | `[u8]` | exactly 64 bytes | secret | `R(32) || s(32)`, zeroised on drop |
| `v` | `u8` | 8 bits | public field of the signed credential | |
| `kid` | `[u8]` | exactly 14 bytes | public field of the signed credential | |
| `c_bytes` | `[u8; 32]` | 256 bits | public commitment | |
| `iat` | `u64` | 64 bits | public field of the signed credential | Big endian within the prehash |
| `exp` | `u64` | 64 bits | public field of the signed credential | Big endian within the prehash |
| `schema` | `[u8]` | exactly 12 bytes | public field of the signed credential | |

The witness MUST be `Clone + Zeroize + ZeroizeOnDrop`. The `Debug` implementation MUST redact all secret fields. `Serialize` and `Deserialize` MUST NOT be implemented for the witness type; serialising witness data outside of the immediate proving call is a privacy violation.

**Validation on construction.** The witness constructor MUST reject inputs that violate the fixed sizes:
- `len(kid) == KID_SIZE_BYTES` (14)
- `len(schema) == SCHEMA_SIZE_BYTES` (12)
- `len(sig_rj_bytes) == 64`
- `len(r_bits) == 128`

Validation that fails MUST return an error; implementations MUST NOT panic.

Source citation: `provii-crypto/crypto-circuit-age/src/lib.rs`, `AgeWitness`.

### 12.5 Constraint Count

The R1CS constraint count is informative: it is an implementation detail that does not affect interoperability. The public input count, `ic.len()`, and proof size are normative and MUST match the values below. Two conforming implementations that emit the same public inputs and proof bytes interoperate irrespective of any minor constraint-count drift; a drift in the constraint count is permitted if and only if the resulting `vk_id` and circuit-constants hash remain bit-identical to the pinned values in Section 13.7.

| Quantity | Value | Status |
|---|---|---|
| R1CS constraints | 99 083 | Informative |
| Public inputs declared | 8 | Normative |
| `ic.len()` (with implicit 1) | 9 | Normative |
| Proof size | 192 bytes | Normative |
| Proving key size | 51 844 344 bytes (≈ 49.6 MiB) |
| Verifying key size | 1 732 bytes |

These values are normative for the v0.1 circuit and are pinned in the manifest (Section 13.7).

### 12.6 Circuit Constants Hash

The circuit constants hash is a Blake2s-256 fingerprint over all constants whose change would alter the R1CS structure. Implementations MUST compute and verify this hash at startup and MUST reject any proving or verifying key whose manifest does not pin a matching value.

```
compute_circuit_constants_hash() = H_b2s(
    b"provii.age.circuit.constants.v0"           // 31 bytes, version-tagged DST
 || SPENDING_KEY_GEN_BYTES                       // 32 bytes (Section 4.3)
 || PROVII_RJ_PERSONALIZATION                    // 8 bytes ("ProviiRJ")
 || NULLIFIER_DST                                // 28 bytes
 || CRED_DST                                  // 14 bytes
 || [0x09, 0, 0, 0, 0, 0]                        // NoteCommitment personalisation
 || LE(KID_SIZE_BYTES, 4)                        // 14 → 4 bytes
 || LE(SCHEMA_SIZE_BYTES, 4)                     // 12 → 4 bytes
 || LE(128, 4)                                   // r_bits length → 4 bytes
)
```

For the v0.1 configuration this evaluates to:

```
9dbbab7e903507b182d1d33f47c72b004e0ffb1bee2cd5ac55e7cbe060338f22
```

Any change to any input listed above is a trusted setup breaking change. The version tag MUST be bumped (currently `v0`) and the parameter file MUST be regenerated. Implementations consuming proving or verifying keys MUST reject parameters whose manifest's `circuit_constants_hash` does not match the implementation's computed value.

Note: the 6 byte sequence `[0x09, 0, 0, 0, 0, 0]` is a fingerprint discriminator for the `NoteCommitment` personalisation (derived from the Sapling internal tuple encoding), not the 6 personalisation bits `111111` fed to the in circuit Pedersen hash (see §5.2). It appears here only as an input to the Blake2s constants fingerprint so that any future change of Pedersen personalisation invalidates the circuit identity.

Source citation: `provii-crypto/crypto-circuit-age/src/lib.rs` (`compute_circuit_constants_hash`).

### 12.7 Synthesis Steps

The `synthesize` function proceeds in 9 numbered steps (steps 0 through 8). Each step adds a defined set of R1CS constraints. The total constraint count is 99 083.

**Step 0. Allocate public inputs.**
- Allocate `direction_bit` as a single Boolean public input.
- Allocate `cutoff_bits` as 32 LE bits (public input).
- Allocate `rp_hash_bits` as 256 bits (public input).
- Allocate `issuer_vk_bits_public` as 256 bits (public input).
- Allocate `cred_nullifier_bits` as 256 bits (public input).
- Pack the 5 conceptual values into 8 field elements via `multipack::pack_into_inputs` in the order: direction → cutoff → rp_hash → issuer_vk → nullifier.

**Step 1. Allocate witness inputs.**
- Allocate the witness bit vectors: `dob_bits` (32), `r_bits` (128), `issuer_vk_bits` (256), `sig_rj_bits` (512), `v_bits` (8), `kid_bits` (112), `c_bytes_bits` (256), `iat_bits` (64), `exp_bits` (64), `schema_bits` (96).
- Validate witness sizes match constants. A mismatch returns `SynthesisError::Unsatisfiable`.

**Step 2. Verify issuer VK equality.**
- Enforce bit by bit equality: `issuer_vk_bits(witness) == issuer_vk_bits_public`.
- This binds the in circuit signature verification to the publicly declared issuer key.

**Step 3. Verify credential nullifier.**
- Compute in circuit: `nullifier' = pedersen_nullifier_gadget(c_bytes_bits)` where the gadget reproduces Section 9.4's bit layout exactly.
- Enforce bit by bit equality: `nullifier' == cred_nullifier_bits`.
- This binds the proof to a specific commitment for replay prevention.

**Step 4. Verify Pedersen commitment.**
- Compute in circuit: `c' = pedersen_commit_gadget(dob_bits, r_bits)` where the gadget reproduces Section 9.1's bit layout exactly.
- Enforce bit by bit equality: `c' == c_bytes_bits`.
- This proves the prover knows `dob_days` and `r_bits` that open the public commitment.

**Step 5. Age check (direction-dependent).**

The conditional swap selects operand order based on the direction bit:
```
For each i in 0..32:
    left[i]  = direction_bit * cutoff_bits[i] + (1 - direction_bit) * dob_bits[i]
    right[i] = direction_bit * dob_bits[i]    + (1 - direction_bit) * cutoff_bits[i]
```
This costs 4 R1CS multiplication constraints per bit (two per operand), totalling 128 constraints over 32 bits. The direction bit is constrained to be Boolean (allocated as a single bit) which costs 1 constraint.

The age check then enforces `left >= right` via a bit-by-bit borrow chain. For each bit position `i`:
```
left[i] - right[i] - borrow[i] = difference[i] - 2 * next_borrow
```
The final borrow at the most significant bit MUST be zero, proving no underflow occurred. This construction is constant time with respect to the input values.

Both `cutoff_days` and `dob_days` are biased from signed `i32` to unsigned `u32` via `bias_for_circuit(x) = (x as u32) XOR 0x8000_0000` (Section 6.3). The bias preserves signed ordering under unsigned comparison.

**Step 6. Build credential prehash message bits.**
- Construct the in circuit byte sequence:
  ```
  CRED_DST_bits (14*8)
   || v_bits (8)
   || kid_len_bits (8, fixed to 14 since len(kid) is fixed)
   || kid_bits (112)
   || c_bytes_bits (256)
   || iat_bits_be (64, big endian)
   || exp_bits_be (64, big endian)
   || schema_len_bits (8, fixed to 12)
   || schema_bits (96)
  ```
- Note `iat` and `exp` are big endian within the circuit, matching Section 8.2.
- All field sizes are fixed (kid=14, schema=12), so the constraint structure is deterministic.

**Step 7. Blake2s hash of the prehash.**
- Compute `msg_hash_bits = Blake2s256(prehash_bits)` in circuit using the Bellman Blake2s gadget.
- No personalisation is used, matching the off circuit `H_b2s(prehash)` call in Section 8.5.
- Output is 256 bits.

**Step 8. Verify RedJubjub signature.**
- Decode `R = R_bytes_bits` and `VK = issuer_vk_bits` as Jubjub subgroup points; assert each is not small order.
- Recompute `c` in circuit via Blake2s with personalisation `PROVII_RJ_PERSONALIZATION` over `R_bytes_bits || VK_bytes_bits || msg_hash_bits` (matching Section 8.4).
- Consume the 256 bit Blake2s output as the scalar for the subsequent scalar multiplication directly. The in-circuit scalar multiplication gadget accepts a 256 bit bit vector and internally treats it as an element of `Fr_J` reduced modulo the Jubjub scalar field order. No explicit `from_bytes_wide` style reduction is performed; Jubjub's scalar field capacity is 251 bits, and the top bits of a Blake2s output are absorbed by the scalar multiplication's MSB handling. Implementations MUST match this behaviour bit-for-bit with the reference circuit; any alternate reduction changes `vk_id`.
- Enforce `[s] G == R + [c] VK` by comparing the u and v coordinates of the resulting points bit by bit.
- This proves the credential was signed by the declared issuer without revealing the signature or the credential message.

The circuit uses only the non RP bound RedJubjub variant. The RP hash is bound to the proof via the `rp_hash` public input only; it does not flow into the credential signature.

Source citation: `provii-crypto/crypto-circuit-age/src/gadgets/`.

### 12.8 Gadget Modules

| Module | Purpose |
|---|---|
| `gadgets/bits.rs` | Bit allocation, `enforce_ge`, `enforce_bits_equal`, `conditional_swap`, u32/u64/u8 witness allocation |
| `gadgets/pedersen.rs` | In circuit Pedersen commitment and nullifier; byte equality |
| `gadgets/blake2s.rs` | In circuit Blake2s-256 hashing |
| `gadgets/redjubjub.rs` | In circuit RedJubjub signature verification, VK and signature allocation |
| `gadgets/prehash.rs` | In circuit credential message transcript construction |
| `gadgets/sapling_ecc.rs` | In circuit Jubjub curve point arithmetic ported from Sapling |
| `gadgets/sapling_pedersen.rs` | In circuit Pedersen hash primitives ported from Sapling |
| `gadgets/sapling_constants.rs` | Pedersen generator tables and circuit constants ported from Sapling |

### 12.9 Expiry Enforcement is Wallet Side in v0.1

A wallet can generate a valid Groth16 proof from an expired credential, and the proof verifies cryptographically. The credential's `iat` and `exp` are part of the signed prehash and are constrained inside the circuit only insofar as the Pedersen commitment and signature must be consistent with them; the circuit does not compare `exp` against the current time.

The Verifier in v0.1 does not receive `iat` or `exp`. The credential body (including `iat`, `exp`, `kid`, and `schema`) is held inside the wallet's witness and never crosses the wire during verification. The Verifier CANNOT enforce credential expiry in v0.1.

Therefore the Wallet MUST enforce credential expiry during preflight (Section 13.5). A conforming Wallet MUST refuse to generate a proof from a credential where `exp <= current_time`, allowing for `CLOCK_SKEW_TOLERANCE_SECONDS` (30) of tolerance.

A conforming Verifier MAY instruct a wallet to refresh its credential if the Verifier has out-of-band knowledge of a revocation or expiry policy, but it MUST NOT depend on receiving `iat` or `exp` from the submission. Section 14.6 specifies the verifier-side flow.

This design choice keeps the circuit small. Encoding "current time" in circuit would require either a trusted time oracle or a very large constraint count for time arithmetic. The chosen approach trades a single off circuit time comparison at the wallet for thousands of avoided constraints and a smaller submission payload.

The security implications of this choice are documented in Section 17.11 (Expiry Trust Assumption).

---

## 13. Prover and Verifier Protocols

### 13.1 Groth16 Parameters

| Parameter | Value |
|---|---|
| Proving system | Groth16 [Groth16] |
| Pairing curve | BLS12-381 |
| Constraint count | 99 083 |
| Public inputs declared | 8 |
| `ic.len()` (with implicit 1) | 9 |
| Proof size | 192 bytes (48 + 96 + 48; A + B + C compressed) |
| Single proving key serves all users | Yes |
| Trusted setup | One time MPC ceremony per circuit version |

The same proving and verifying key pair serves all users for a given protocol version. Wallets do not need per user setup.

The proving key is approximately 50 megabytes and is distributed to wallets via a CDN. The verifying key is 1 732 bytes and is shipped with verifier configurations.

### 13.2 RP Challenge and RP Hash

The Verifier derives `rp_challenge` deterministically at the time it creates a new challenge record (Section 14.2). The derivation binds the challenge to the requesting origin and a fresh nonce:

```
CHALLENGE_DST = "provii.challenge.v0"
rp_challenge  = SHA-256(origin || nonce || CHALLENGE_DST)   // 32 bytes
```

The `nonce` is 32 bytes drawn from a CSPRNG. The origin is the raw byte string of the Relying Party's WHATWG origin. Because the origin is hashed into `rp_challenge`, a proof generated for one origin cannot be replayed against a different origin even if the nonce were reused.

`rp_hash` is the circuit public input derived from `rp_challenge`:

```
rp_hash = H_b2s(rp_challenge)                 // 32 bytes, no personalisation
```

The Wallet computes `rp_hash` exactly this way before generating its proof. The Verifier computes the same value when checking the submission. The 32 byte `rp_hash` is what flows into the public input vector at indices 2 and 3.

Blake2s-256 is used here because it is cheap in R1CS; the in-circuit cost of the wrap step is small compared to the surrounding Pedersen and signature gadgets.

**Origin handling.** The origin string flows into `rp_challenge` via the derivation above, and therefore transitively into `rp_hash`. It is also recorded in the Verifier's challenge record (Section 14.2) for origin policy lookup, audit logging, and rate-limit keying. The origin byte string MUST satisfy:

- It is a valid WHATWG origin (scheme, host, and optional port; no path, query, or fragment).
- Each byte is a printable ASCII character in the range `0x21..=0x7E`. Implementations MUST reject null bytes, any byte below `0x20`, and any byte `>= 0x7F`.
- `len(origin)` is at least 1 and at most 2048 bytes.

Implementations MUST reject origins that fail any of these checks before storing a challenge record.

Source citations: `provii-crypto/crypto-protocol/src/lib.rs` (derivation function), `provii-verifier/src/routes/challenge.rs` (challenge creation), `provii-verifier/src/routes/verify.rs` (verify step), `provii-mobile-sdk/crates/core/src/prover.rs` (prover step).

### 13.3 Origin Hash

A simple SHA-256 over the origin string, used for replay tag computation and audit logging:

```
compute_origin_hash(origin):
    return H_sha256(origin.as_bytes())        // 32 bytes
```

Origin strings MUST be compared and hashed byte for byte. Implementations MUST NOT normalise case (`Example.com` and `example.com` are distinct origins for this protocol), trim whitespace, decode percent escapes, or punycode normalise.

### 13.4 PKCE ([RFC7636], S256)

PKCE is used to bind the party that initiated the verification challenge to the party that redeems the result. Provii uses the S256 method exclusively.

```
code_verifier   <- 43 to 128 character string over the RFC 7636
                   unreserved alphabet (ALPHA / DIGIT / "-" / "." /
                   "_" / "~"), generated by the Relying Party, kept
                   private
code_challenge  = base64url_no_pad(H_sha256(code_verifier))
                                              // 43 characters
```

The `code_challenge` is presented by the Relying Party to the Verifier when the challenge is generated (Section 14.2). The `code_verifier` is presented by the Relying Party to the Verifier at result redemption (Section 14.7). The Verifier validates:

```
stored_hash = base64url_decode(stored_code_challenge)    // 32 bytes
received_hash = H_sha256(code_verifier)                  // 32 bytes
require constant_time_eq(stored_hash, received_hash)
```

The comparison is performed over the 32 raw bytes of each SHA-256 output, not over the base64url string form, to ensure a single canonical byte-level equality check. The validation MUST occur at result redemption time (when the Relying Party retrieves the result), NOT at proof submission time. The Wallet does not see the `code_verifier`; it sees only the `challenge_id`, `rp_challenge`, `cutoff_days`, `verifying_key_id`, `proof_direction`, and `submit_secret` (Section 14.3).

Implementations MUST use a constant time comparison for the validation step, using `subtle::ConstantTimeEq::ct_eq` or an equivalent platform primitive.

### 13.5 Wallet Preflight

Before generating a Groth16 proof (which costs seconds of CPU), a conforming Wallet MUST perform the following preflight checks. Failing fast on any of these saves the user from waiting on a proof that the Verifier will reject.

```
Preflight(challenge, credential, dob_days, r_bits):
    1. Recompute the commitment: c' = PedersenCommit(dob_days, r_bits)
       require c' == credential.c                  // bit equality

    2. Verify the issuer signature off circuit:
       require Verify(credential.issuer_vk, credential, credential.signature)

    3. Verify the credential is not expired AND the validity
       window is plausible:
       require credential.iat < credential.exp
       require credential.iat <= current_time + CLOCK_SKEW_TOLERANCE_SECONDS
       require credential.exp > current_time
       require credential.exp - credential.iat <= MAX_VALIDITY_SECONDS
       require credential.exp <= current_time + MAX_VALIDITY_SECONDS

    4. Verify the age predicate is satisfied locally:
       biased_dob    = bias_for_circuit(dob_days)
       biased_cutoff = bias_for_circuit(challenge.cutoff_days)
       if challenge.direction == Over:
           require biased_cutoff >= biased_dob     // unsigned compare
       else:  // Under
           require biased_dob >= biased_cutoff

    5. Verify the issuer's VK matches the wallet's local issuer registry:
       require credential.issuer_vk is recognised

    6. Verify the proving key is the right vk_id by checking the
       wallet's loaded proving key's manifest vk_id.
```

If preflight step 3 (credential expiry) fails, the Wallet MUST NOT generate a proof. If any other preflight step fails, the Wallet SHOULD NOT generate a proof and in all cases MUST NOT submit a proof that does not pass local verification. The Wallet SHOULD surface the relevant failure to the user (for example, "your credential has expired; please re-enrol").

These preflight checks are normative and are specified by the proof generation requirements in this section.

### 13.6 Public Input Assembly

The `assemble_public_inputs_canonical` function packs public values into 8 BLS12-381 scalar field elements via the multipack algorithm. 32 bit values fit in a single field element. 256 bit values are split at the BLS12-381 scalar capacity (254 bits) into 2 field elements each.

```
AssemblePublicInputs(direction, cutoff_days, rp_hash, issuer_vk, cred_nullifier):
    inputs = []

    // 0. Direction: 1 bit packed as a 32 bit u32 (high bits zero)
    dir_u32 = 1 if direction == Over else 0
    inputs.extend(multipack(bits_le(LE(dir_u32, 4))))            // 1 element

    // 1. Cutoff days: biased u32 → 32 LE bits
    biased_cutoff = bias_for_circuit(cutoff_days)
    inputs.extend(multipack(bits_le(LE(biased_cutoff, 4))))      // 1 element

    // 2-3. RP hash: 32 bytes → 256 LE bits
    inputs.extend(multipack(bits_le(rp_hash)))                   // 2 elements

    // 4-5. Issuer VK: 32 bytes → 256 LE bits
    inputs.extend(multipack(bits_le(issuer_vk)))                 // 2 elements

    // 6-7. Nullifier: 32 bytes → 256 LE bits
    inputs.extend(multipack(bits_le(cred_nullifier)))            // 2 elements

    require len(inputs) == 8
    return inputs
```

**Order is critical.** The packing order MUST match exactly between the prover circuit (Section 12.7 step 0) and the verifier (this section). A mismatch causes silent verification failure: the proof verifies to false but no diagnostic indicates which input was misordered.

**Bit 254 preservation.** The implementation uses a manual packing routine alongside `multipack::compute_multipacking` to ensure bit 254 of 256 bit values is not dropped during chunking. Implementations MUST preserve this bit.

### 13.7 Verifying Key Identification

Each Groth16 verifying key is identified by a 32 bit `vk_id` derived as follows:

```
vk_fingerprint = H_b2s(vk_bytes)                 // 32 bytes
vk_id          = u32_le(H_b2s(VK_ID_DST || vk_bytes)[0..4])
                                                  // VK_ID_DST = "provii.vk.id.v0"
```

The `vk_bytes` are the canonical Bellman serialised verifying key [Bellman] (`bellman::groth16::VerifyingKey<Bls12>::write`).

The Verifier maintains a registry mapping `vk_id` to `PreparedVerifyingKey`:
```
VK_REGISTRY: Mapping<u32, PreparedVerifyingKey<Bls12>>  // implementations may use any in-memory map keyed on the circuit version
```

The registry MUST support multiple `vk_id` values to enable algorithm and parameter agility. When an implementation rotates the trusted setup or bumps the circuit constants version, both the old and new `vk_id` may briefly coexist in the registry until the old `vk_id`'s population of in flight proofs has drained.

For the v0.1 deployed parameters:

| Field | Value |
|---|---|
| `vk_id` | `914153247` |
| `vk_fingerprint_blake2s` | `3491e619259f47b7c5b3b82ed6f71a3bf62a6c2e5a5e9349163e8c0e94c73644` |
| `vk_blake2b512_hash` | `0aed1bda4ad79cd0c166976c5ee3f2bd1f9ca983ba8af5a7c45224003a356eac6acc61209250fd08e4835994147ca2ebc8b5e3fb6abdbbaaf2cccab566bedc0a` |
| `vk_size` | 1732 bytes |
| `pk_size` | 51 844 344 bytes |
| `pk_blake2s_hash` | `375e8913b13e234b660bf24995856c7ee59d8fc24462312714e6eebac63c745e` |
| `circuit_constants_hash` | `9dbbab7e903507b182d1d33f47c72b004e0ffb1bee2cd5ac55e7cbe060338f22` |
| `constraints` | 99 083 |
| `public_inputs` | 8 |
| `ic_len` | 9 |
| `kid_bytes` | 14 |
| `schema_bytes` | 12 |

These values are pinned in the manifest files `provii-crypto/age_pk.914153247.manifest.json` and `provii-crypto/zk-params-manifest.json`.

Source citation: `provii-crypto/crypto-circuit-age/examples/check_key.rs`.

### 13.8 Proving Key Distribution and Integrity

The Groth16 proving key is large (≈ 50 MiB) and is not shipped with the wallet binary. Wallets download the proving key from a CDN URL on first use and cache it.

Conforming Wallet implementations MUST perform the following integrity checks on every proving key download:

1. **Size check.** The downloaded byte count MUST equal the manifest's `pk_size` exactly.
2. **Content hash check.** `H_b2s(pk_bytes)` MUST equal the manifest's `pk_blake2s_hash` exactly. Comparison MUST be byte for byte.
3. **VK fingerprint check.** After parsing the proving key, `H_b2s(vk.write_bytes())` MUST equal the manifest's `vk_fingerprint_blake2s` exactly.
4. **Circuit constants check.** The wallet's local `compute_circuit_constants_hash()` value MUST equal the manifest's `circuit_constants_hash` exactly.

Any failure MUST cause the wallet to discard the downloaded file and refuse to generate proofs until a successful download is achieved. Implementations MUST NOT silently fall back to an older cached proving key whose `vk_id` has been retired.

Retry policy for transient failures (network timeout, partial body, non-2xx response on the bytes endpoint, or integrity check mismatch). A conforming Wallet:

1. MUST use exponential backoff starting at 2 seconds, doubling on each retry, capped at 60 seconds between attempts.
2. MUST apply full jitter (a uniform random fraction of the current backoff window) to the delay before each retry to avoid thundering herds when many wallets refresh simultaneously.
3. MUST NOT exceed 5 retries within a single 24 hour window for the same `vk_id`. After the fifth failure the Wallet MUST surface a user-visible error and MUST NOT silently mask the condition.
4. MUST treat each integrity failure (size, hash, VK fingerprint, or circuit constants mismatch) as a hard failure of that attempt and count it against the retry budget.
5. MUST NOT resume from an integrity-failed partial download; subsequent attempts MUST start from zero bytes.

Wallets SHOULD verify available disk space before initiating download: at least 60 megabytes free is required as an absolute floor (proving key plus intermediate parse buffer). Wallets SHOULD refuse to start the download if less than 100 megabytes are free, to leave margin for concurrent OS activity. A disk-full failure during download MUST be treated as a transient failure for retry accounting purposes.

The `vk_id` MUST be embedded in proof submissions (Section 14.5) so the Verifier can route the proof to the correct verifying key.

### 13.9 Proof Generation

```
Prove(params, direction, cutoff_days, rp_hash, witness):
    public = AgePublic {
        direction,
        cutoff_days,
        rp_hash,
        issuer_vk_bytes:  witness.issuer_vk_bytes,
        cred_nullifier:   PedersenNullifier(witness.c_bytes),
    }
    circuit = AgeCircuit { public, witness }
    proof   = Groth16.prove(params, circuit)              // 192 bytes
    public_inputs = AssemblePublicInputs(
        direction, cutoff_days, rp_hash,
        witness.issuer_vk_bytes, public.cred_nullifier,
    )
    return (proof, public_inputs)
```

Implementations MUST zeroise all secret witness fields (those marked `secret` in Section 12.4) after the prove call returns.

### 13.10 Proof Verification

```
Verify(vk, proof_bytes, direction, cutoff_days, rp_hash,
       issuer_vk, cred_nullifier):
    public_inputs = AssemblePublicInputs(
        direction, cutoff_days, rp_hash, issuer_vk, cred_nullifier,
    )
    proof = bellman::groth16::Proof::read(proof_bytes)    // see Section 15.5
    return bellman::groth16::verify_proof(vk, proof, public_inputs)
```

Implementations MUST use the canonical Bellman serialisation [Bellman] for proof bytes (Section 15.5). Implementations that parse arkworks serialisation (or any other format) MUST detect the format mismatch and reject; the byte layouts differ.

A conforming Verifier MUST validate `len(proof_bytes) == 192` before parsing. The canonical Groth16 over BLS12-381 proof is exactly 192 bytes (48 byte compressed G1 A || 96 byte compressed G2 B || 48 byte compressed G1 C). The reference implementation's wire type enforces this length as the only accepted value.

---

## 14. Verification Protocol

This section specifies the full verification flow as a numbered sequence of normative steps.

Provii defines two integration profiles. Both terminate at the same Verifier; they differ in how the Relying Party authenticates to the Verifier and in whether a Provii-operated HTTP intermediary (the simple verification service) relays the call.

| Profile | Relying Party target | Authentication | Typical deployment |
|---|---|---|---|
| Simple | Simple verification service (Provii-operated) | Origin header + API token minted at registration | Websites adopting Provii via a drop-in client |
| Expert | Verifier directly | HMAC-SHA256 over `CLIENT_ID` + canonical request + PKCE `code_challenge` | Enterprise integrations, mobile SDK users |

The Simple profile is normatively specified by delegation: the simple verification service forwards the Relying Party's request to the Verifier using the Expert profile's wire format, with `origin` set from the Relying Party's registered origin and `proof_direction` derived from the origin's policy record. A Simple-profile Relying Party MUST treat the simple verification service's responses as if they came from the Verifier; this specification's invariants about what the Relying Party MAY and MUST NOT learn apply equally in both profiles.

The numbered steps in Sections 14.2 through 14.7 describe the Expert profile end-to-end. Where Simple-profile behaviour differs, the difference is called out inline.

### 14.1 Preconditions

Before verification can begin:

1. The Verifier has loaded one or more `PreparedVerifyingKey` instances into its `VK_REGISTRY`, each indexed by `verifying_key_id`.
2. The Verifier has loaded an issuer registry mapping `issuer_vk_bytes` to issuer metadata (display name, status, allowlist membership). Issuers not in the registry MUST be rejected at verification time.
3. The Relying Party (Expert profile) has been provisioned with a `CLIENT_ID` and HMAC-SHA256 client secret at the Verifier; has registered its origin and chosen a `proof_direction` policy (`"over_age"` or `"under_age"`) for that origin.
4. The Wallet has a SignedCredential whose `issuer_vk` is in the Verifier's issuer registry.
5. The Wallet has downloaded and integrity verified a proving key whose `verifying_key_id` matches a `verifying_key_id` in the Verifier's `VK_REGISTRY`.

### 14.2 Challenge Generation

```
Step 1.  The Relying Party requests a challenge from the Verifier
         with parameters:
             origin            // HTTP Origin header
             method            // "POST"
             cutoff_days       // i32, threshold
             expires_in        // <= CHALLENGE_EXPIRY_SECONDS (300)
             code_challenge    // PKCE S256 code challenge (43 chars)
             verifying_key_id  // u32, the VK the Wallet will use
             authorizer        // canonical client identity (CLIENT_ID)
         Authentication: HMAC-SHA256 over the canonical request.

Step 2.  The Verifier looks up the origin's policy record and derives
         proof_direction from it (the Relying Party does not supply
         direction; it is a property of the registered origin).

Step 3.  The Verifier generates:
             challenge_id     = UUIDv4 canonical hyphenated form
                                 ([RFC9562])
             nonce            = 32 bytes from CSPRNG
                                 (must pass validate_nonce)
             rp_challenge     = SHA-256(origin || nonce ||
                                 "provii.challenge.v0")
                                 (32 bytes; see Section 13.2)
             submit_secret    = 32 bytes from CSPRNG
                                 (must pass validate_nonce)
             short_code       = 12-digit numeric code
                                 (displayed as XXXX XXXX XXXX,
                                 suitable for verbal handoff)

Step 4.  The Verifier stores a CachedChallenge keyed by challenge_id.
         The full field list appears in Section 15.9; the fields that
         the Verifier uses at submission time are:
             {
                 id:                 challenge_id,
                 rp_challenge,
                 cutoff_days,
                 verifying_key_id,
                 code_challenge,     // from Relying Party
                 submit_secret,
                 origin,
                 expires_at,         // now + expires_in
                 proof_direction,
                 short_code,
                 state:              Pending,
             }

Step 5.  The Verifier returns to the Relying Party:
             {
                 challenge_id,
                 rp_challenge:      base64url_no_pad,
                 cutoff_days,
                 verifying_key_id,
                 submit_secret:     base64url_no_pad,
                 expires_at,
                 proof_direction,
                 short_code,
                 status_url,
                 verify_url,
             }
```

The `expires_in` requested by the Relying Party MUST NOT exceed `CHALLENGE_EXPIRY_SECONDS` (300). Verifiers MAY enforce a tighter ceiling.

Verifiers MUST reject any challenge request with `cutoff_days` outside the inclusive range `[-36525, +36525]`. This matches the `dob_days` sanity range in Section 10.2: a cutoff outside this range cannot correspond to a plausible date of birth and is either a malformed request or an attempt to exploit wraparound arithmetic in the biasing transform (Section 6.3).

The `nonce` input to `rp_challenge` derivation MUST satisfy `validate_nonce`: length exactly 32 bytes, at least 8 distinct byte values, not all zero. CSPRNG output overwhelmingly satisfies these properties; the validation is defence in depth. The resulting `rp_challenge` (a SHA-256 output) inherits high entropy from a valid nonce. The same `validate_nonce` predicate applies uniformly to every 32 byte random value minted by a Provii role: the nonce for `rp_challenge` derivation, the `submit_secret`, the attestation nonce (Section 10), and `r_bits` ingress. A conforming implementation MUST reject any such value that fails `validate_nonce` and MUST NOT substitute a replacement value.

The `submit_secret` MUST be 32 bytes from a CSPRNG. It MUST NOT be derived from any other state in the system. The Verifier returns it ONLY to the Relying Party, not to the Wallet directly. The Relying Party relays it to the Wallet (typically via the same QR code or deep link that conveys the rest of the challenge).

`short_code`, `status_url`, and `verify_url` support polling and alternative handoff patterns (for example, entering the short code verbally at a kiosk). They are returned to the Relying Party in the challenge response; they do not flow into the Wallet's proof generation.

### 14.3 Challenge Delivery to Wallet

The Verifier returns the challenge fields to the Relying Party. The Relying Party delivers them to the Wallet by an out-of-band channel:

- **Desktop to mobile.** The Relying Party renders a QR code encoding the challenge fields. The user scans the QR with the Wallet.
- **Mobile to mobile.** The Relying Party issues a deep link with the challenge fields as query parameters.
- **Mobile to embedded.** A web view or app-internal path delivers the fields directly.
- **Short-code entry.** The user enters `short_code` at the Wallet; the Wallet resolves it via the `verify_url` to fetch the remaining challenge fields.

The transport MUST preserve the integrity of the challenge fields. The `submit_secret` is sensitive; if an attacker intercepts the submit_secret and the proof submission they could submit a proof. TLS at the Relying Party boundary is a sufficient defence; Bluetooth or short range channels with their own integrity properties are also acceptable.

### 14.4 Wallet Side Steps

```
Step 6.  The Wallet performs preflight (Section 13.5) on its
         credential against the challenge.

Step 7.  The Wallet computes off circuit:
             cred_nullifier = PedersenNullifier(credential.c)
             rp_hash        = H_b2s(rp_challenge)

Step 8.  The Wallet generates a Groth16 proof:
             (proof, public_inputs) = Prove(
                 params,
                 challenge.proof_direction,
                 challenge.cutoff_days,
                 rp_hash,
                 witness = AgeWitness {
                     dob_days, r_bits,
                     issuer_vk_bytes:  credential.issuer_vk,
                     sig_rj_bytes:     credential.sig_rj,
                     v:      credential.v,
                     kid:    credential.kid,
                     c_bytes: credential.c_bytes,
                     iat:    credential.iat,
                     exp:    credential.exp,
                     schema: credential.schema,
                 },
             )
```

The proof generation step takes seconds on commodity mobile hardware. The wallet SHOULD display progress feedback.

### 14.5 Proof Submission

```
Step 9.  The Wallet submits a SubmitProofRequest to the Verifier at
         POST /v0/verify:
             {
               "challenge_id":   <uuid string>,
               "submit_secret":  <base64url_no_pad; 43 chars>,
               "proof": {
                 "verifying_key_id": <u32>,
                 "public": {
                   "cutoff_days":     <i32>,
                   "rp_challenge":    <base64url_no_pad; 43 chars>,
                   "issuer": { "value": <base64url_no_pad; 43 chars> },
                   "cred_nullifier":  <base64url_no_pad; 43 chars>
                 },
                 "proof": <base64url_no_pad; 256 chars = 192 bytes>
               }
             }
```

**Critical invariant.** The Wallet does NOT include `proof_direction` in the submission. The Verifier retrieves it from the stored CachedChallenge (Section 14.2 step 4). This prevents a Wallet from substituting a different direction at submission time.

**Critical invariant.** The Wallet submits the raw `rp_challenge` (32 bytes), not the `rp_hash` (Blake2s wrap). The Verifier independently computes `rp_hash = H_b2s(rp_challenge)` and cross checks it against the value packed into the proof's public inputs. The Wallet supplies the raw value so the Verifier can cross check.

### 14.6 Verifier Side Steps

```
Step 10. The Verifier processes the submission:

   10a. Lookup the CachedChallenge by challenge_id. If not found,
        expired, or already consumed, return ApiError::BadRequest
        with code "CHALLENGE_NOT_FOUND" or "CHALLENGE_EXPIRED" or
        "CHALLENGE_ALREADY_CONSUMED".

   10b. Validate submit_secret in CONSTANT TIME against the stored
        value (using subtle::ConstantTimeEq::ct_eq or hmac::Mac
        ::verify_slice). On mismatch, return ApiError::BadRequest
        with code "INVALID_SUBMIT_SECRET".

   10c. Validate the submitted rp_challenge in CONSTANT TIME against
        the stored rp_challenge. On mismatch, return
        ApiError::BadRequest with code "INVALID_CHALLENGE".

   10d. Compute rp_hash = H_b2s(rp_challenge).

   10e. Check the cred_nullifier against the Verifier's ban store.
        On ban, return ApiError::BadRequest with code
        "CREDENTIAL_BANNED".

   10f. Look up the issuer in the issuer registry by issuer_vk_bytes.
        If not present or status is not Active, return
        ApiError::BadRequest with code "UNKNOWN_ISSUER".

   10g. Look up the verifying key in VK_REGISTRY by verifying_key_id.
        If not present, return ApiError::BadRequest with code
        "UNKNOWN_VERIFYING_KEY".

   10h. The Verifier does not receive iat/exp in v0.1 and cannot
        enforce credential expiry; see Sections 12.9 and 17.11.

   10i. Assemble the public inputs vector (Section 13.6) using
        proof_direction from the stored CachedChallenge, cutoff_days
        from the submission (cross checked against the stored
        record), rp_hash from 10d, issuer_vk from the submission, and
        cred_nullifier from the submission.

   10j. Verify the Groth16 proof:
            result = bellman::groth16::verify_proof(vk, proof,
                                                     public_inputs)
        On false, return ApiError::BadRequest with code
        "INVALID_PROOF".

   10k. Transition the CachedChallenge from Pending to
        ProofOkWaitingForRedeem (on success) or Failed (on a non-
        replay failure that would have consumed the challenge).
        Record the result and the timestamp.

Step 11. The Verifier returns a success response to the Wallet (or a
         precise ApiError if any step failed). The Wallet-facing
         response contains no verification outcome; the outcome is
         reserved for the Relying Party's redeem call.
```

All comparisons of secret material in steps 10b and 10c MUST use constant-time comparison (`subtle::ConstantTimeEq::ct_eq` or `hmac::Mac::verify_slice`). String comparisons are prohibited. Comparisons of public material (challenge_id, verifying_key_id, issuer_vk lookup) MAY use ordinary equality.

The challenge expiry check is implicit in step 10a: an expired challenge MUST be removed from the active store and any submission MUST fail at lookup. Implementations SHOULD eagerly evict expired challenges to bound the active store size.

### 14.7 Result Redemption

```
Step 12. The Relying Party redeems the result by presenting the PKCE
         code_verifier to the Verifier:
             POST /v0/challenge/:challenge_id/redeem
             Authentication: HMAC-SHA256 (Expert profile) or origin
             + API token (Simple profile).
             Body: { "code_verifier": <string> }

Step 13. The Verifier validates:
             stored   = base64url_decode(stored.code_challenge)
             received = H_sha256(code_verifier)
             require constant_time_eq(stored, received)
             require CachedChallenge.state == ProofOkWaitingForRedeem
             Transition CachedChallenge state to Verified.
             Return { "result": "OK", "verified": <bool> }
             where verified is the verification outcome recorded in
             step 10k.
```

PKCE validation occurs at redemption, NOT during proof submission. This separation ensures the party redeeming the result is the same party that initiated the challenge.

The response returned to the Relying Party is the binary verification outcome only. The Relying Party MUST NOT receive the proof, the public inputs, the wallet identity, the nullifier, or any data that could deanonymise the user.

### 14.8 Cutoff Days Computation

The Relying Party specifies an age threshold (for example, "at least 18 years old"). The Verifier converts this to a `cutoff_days` value as days since the Unix epoch.

```
cutoff_days = days_between(EPOCH, date_n_years_ago(now, n))
```

where `date_n_years_ago(now, n)` is the calendar date `n` years before `now`, accounting for leap years. For example, if today is 2026-04-13 and `n = 18`, then `date_n_years_ago = 2008-04-13`, and `cutoff_days` is the count of days from 1970-01-01 to 2008-04-13.

An alternative computation is `cutoff_days = floor(now_days - n * 365.25)`. This is approximate (may disagree by one day at year boundaries) but cheaper. Implementations MAY use either; the choice does not affect interoperability since `cutoff_days` is a public input transmitted alongside the proof.

### 14.9 Replay Protection and Ban Enforcement

Replay protection prevents a captured proof from being submitted twice, or its verification outcome from being redeemed by a party other than the one that initiated the challenge. Replay is blocked at two distinct points in the flow.

**Submission-blocking defences.** Four layers operate at proof submission (Section 14.5). A captured proof cannot be resubmitted if any one of these holds.

| Submission-blocking layer | Mechanism |
|---|---|
| Single-use challenge | CachedChallenge state moves from Pending to ProofOkWaitingForRedeem or Failed on first valid submission. Subsequent submissions against the same `challenge_id` MUST be rejected at lookup. |
| Submit secret | The 32 byte `submit_secret` is shared only from Relying Party to Wallet; third parties observing the public challenge cannot reconstruct it and cannot submit. |
| `rp_challenge` binding | The `rp_challenge` flows through the proof's `rp_hash` public input. A proof generated for one challenge does not satisfy a different challenge's public inputs. |
| Challenge expiry | Challenges expire after `CHALLENGE_EXPIRY_SECONDS` (300 seconds), bounding the replay window even if the other defences were somehow bypassed. |

**Redemption-blocking defence.** PKCE operates at result redemption (Section 14.7), not at submission. A third party that somehow succeeds in submitting a captured proof still cannot claim the verification outcome, because redemption requires presenting the PKCE `code_verifier` known only to the party that supplied the original `code_challenge`.

**Ban enforcement.** The Verifier maintains a nullifier ban store as a persistent list of nullifiers belonging to credentials known to be abusive or compromised. The store is managed by a Verifier-side administrative process (typically an operator console writing to durable storage); entries are added and removed by operator action, not automatically by verification events. Entries persist until an operator removes them; there is no TTL. Any submitted proof whose nullifier matches a banned entry is rejected with the `CREDENTIAL_BANNED` code. This lets the Verifier block specific credentials independently of whether any given proof is a replay.

---

## 15. Wire Formats

This section consolidates all wire visible byte layouts. The constructions are normative; implementations MUST produce and consume bytes exactly as specified.

### 15.1 Credential Prehash

Off circuit byte layout for input to `H_b2s`:

```
Offset  Length  Field
------  ------  -----
0       14      CRED_DST                ("provii.cred.v0")
14      1       v                          (u8 version)
15      1       kid_len                    (u8; rejects > 255; production = 14)
16      kid_len kid                        (UTF-8)
16+     32      c                          (Pedersen commitment, 32 bytes)
48+     8       iat                        (BE u64, big endian)
56+     8       exp                        (BE u64, big endian)
64+     1       schema_len                 (u8; rejects > 255; production = 12)
65+     ...     schema                     (UTF-8)
```

For production credentials with `kid_len = 14` and `schema_len = 12`, the prehash is exactly `14 + 1 + 1 + 14 + 32 + 8 + 8 + 1 + 12 = 91 bytes`.

### 15.2 Signed Credential

The public-only structure returned by the Issuer to the Wallet on the wire. In the reference implementation this is `SignedCredentialHeader` in `provii-mobile-sdk/crates/core/src/types.rs`; the Wallet attaches the private witnesses (`dob_days`, `r_bits`) locally after receipt.

Rust declaration (canonical field order is the order declared; serde serialises in declaration order):

```rust
struct SignedCredentialHeader {
    v:          u8,
    kid:        String,           // UTF-8, exactly KID_SIZE_BYTES (14) on the wire
    issuer_vk:  [u8; 32],         // RedJubjub verifying key, base64url no pad
    sig_rj:     [u8; 64],         // RedJubjub signature: R(32) || s(32), base64url no pad
    c_bytes:    [u8; 32],         // Pedersen commitment, base64url no pad
    iat:        u64,              // Unix seconds
    exp:        u64,              // Unix seconds
    schema:     String,           // UTF-8, exactly SCHEMA_SIZE_BYTES (12) on the wire
}
```

Wire encoding (JSON), keys in the serde declaration order above:

```json
{
    "v": 2,
    "kid": "provii:2026-05",
    "issuer_vk": "BASE64URL32...",
    "sig_rj": "BASE64URL64...",
    "c_bytes": "BASE64URL32...",
    "iat": 1704067200,
    "exp": 1735689600,
    "schema": "provii.age/0"
}
```

JSON field order follows serde serialisation of the declared Rust struct; implementations producing or consuming canonical JSON MUST use the field names and nesting shown here. `kid` and `schema` are JSON strings (UTF-8), not base64-encoded byte arrays. `issuer_vk`, `sig_rj`, and `c_bytes` are base64url no pad of the raw byte arrays of lengths 32, 64, and 32 respectively. Implementations MUST reject unknown keys (`#[serde(deny_unknown_fields)]` or equivalent).

Source citation: `provii-mobile-sdk/crates/core/src/types.rs`, `SignedCredentialHeader`.

### 15.3 RedJubjub Signature

```
sig = R_bytes (32) || s_bytes (32)        // 64 bytes total
```

`R_bytes` is the canonical Jubjub compressed point encoding (v coordinate plus sign bit). `s_bytes` is the canonical little endian scalar encoding for `Fr_J`.

Decoding MUST reject:
- non canonical scalar encodings of `s`
- points not in the prime order subgroup
- the identity point
- small subgroup elements

### 15.4 DOB Attestation Message

Input to `H_b2s` for the attestation message (with length-prefixed variable fields):

```
Offset   Length           Field
------   ------           -----
0        25               DOB_ATTESTATION_DST  ("provii.attestation.dob.v0")
25       4                dob_days              (LE i32)
29       1                issuer_id_len         (u8; rejects > 255)
30       issuer_id_len    issuer_id             (UTF-8)
k        8                timestamp             (LE u64)
k+8      32               nonce                 (32 bytes)
k+40     1                session_id_len        (u8; rejects > 255)
k+41     session_id_len   session_id            (UTF-8)
m        1                client_id_len         (u8; rejects > 255)
m+1      client_id_len    client_id             (UTF-8)
```

Where `k = 30 + issuer_id_len` and `m = k + 40 + 1 + session_id_len`.

The output of this Blake2s-256 hash is the 32 byte message that is signed with Ed25519. The 64 byte signature is appended to form the wire `Attestation`:

```
Attestation {
    dob_days:    i32,
    issuer_id:   String,
    timestamp:   u64,
    nonce:       [u8; 32],
    session_id:  String,
    client_id:   String,
    signature:   [u8; 64],
}
```

Wire encoding is JSON with byte fields hex-encoded (lower case ASCII hex, two characters per byte, no separators):

```json
{
    "dob_days": 7300,
    "issuer_id": "provii.id.v0",
    "timestamp": 1704067200,
    "nonce": "HEX64...",
    "session_id": "sess_7f1e...",
    "client_id": "client_acme",
    "signature": "HEX128..."
}
```

The Attestation uses hex encoding rather than the base64url convention of Section 2.7 because Ed25519 attestations are frequently inspected in tools and logs where hex is the established display format. `nonce` is exactly 64 hex characters (32 bytes) and `signature` is exactly 128 hex characters (64 bytes). Implementations MUST reject non-lowercase hex, odd-length hex, and any non-hex character.

JSON numeric precision note. The `timestamp` field is declared u64 (Section 10.2). JSON numbers are, by default, interpreted as IEEE 754 double precision in many popular parsers, which is only safe up to 2^53 - 1. For Unix-second timestamps this is not a practical concern until year 285 428 141. Implementations that need to emit or consume `u64` values elsewhere in the protocol MUST either serialise those values as decimal strings or document and enforce a bound below 2^53.

### 15.5 Groth16 Proof

The Groth16 proof is exactly 192 bytes regardless of statement complexity. The byte layout follows the canonical Bellman serialisation [Bellman]:

```
Offset  Length  Field           Encoding
------  ------  -----           --------
0       48      A               compressed G1, BLS12-381
48      96      B               compressed G2, BLS12-381
144     48      C               compressed G1, BLS12-381
```

`bellman::groth16::Proof::write` produces this exact layout. `bellman::groth16::Proof::read` consumes it. Implementations using arkworks (which produces a different byte order for compressed G2 elements) MUST convert before sending or receiving on the Provii wire.

The compressed G1 encoding is 48 bytes (one field element plus flag bits). The compressed G2 encoding is 96 bytes (two field elements plus flag bits). Both follow [PairingCurves] compression conventions as implemented by the `bls12_381` crate: the most significant bit of the first byte is the compression flag (always `1` for compressed form), the next bit is the infinity flag, and the bit after that encodes the sign of the y-coordinate (a.k.a. the point's `y-lex`). Implementations MUST accept only the compressed form; MUST reject encodings whose compression flag is `0` (which signals the uncompressed form, not used on the Provii wire); and MUST perform subgroup checks after decompression.

Confirmed against `bellman::groth16::Proof::write` (bellman 0.14): the function writes `a.to_compressed()` (48 bytes), then `b.to_compressed()` (96 bytes), then `c.to_compressed()` (48 bytes), in that order, for a total of 192 bytes. The reference test harness at `provii-crypto/crypto-e2e-tests/tests/spec_vectors.rs` (Stage 12) reproduces this layout deterministically.

### 15.6 Public Inputs (JSON)

The wire JSON schema for proof submission public inputs. Rust declaration (canonical field order is the order declared; serde serialises in declaration order):

```rust
struct PublicInputsJson {
    cutoff_days:     i32,
    rp_challenge:    [u8; 32],     // base64url no pad
    issuer:          IssuerKeyJson,
    cred_nullifier:  [u8; 32],     // base64url no pad
}

struct IssuerKeyJson {
    value:           [u8; 32],     // raw RedJubjub verifying key, base64url no pad
}
```

Wire encoding (JSON), keys in the serde declaration order above:

```json
{
    "cutoff_days":     11246,
    "rp_challenge":    "BASE64URL32...",
    "issuer": {
        "value":       "BASE64URL32..."
    },
    "cred_nullifier":  "BASE64URL32..."
}
```

The nested issuer object uses the field name `value`, not `vk`. The wire field is the raw 32 byte RedJubjub verifying key, not a hash.

Encoding rules:
- Base64url with no padding throughout for binary fields. Decoders MUST reject padding characters and non URL safe characters. Decoders MUST also reject encodings whose final character carries non-zero padding bits, per [RFC4648] Section 3.5 (see Section 2.7).
- A 32 byte value encodes to exactly 43 characters.
- A 192 byte value encodes to exactly 256 characters.
- JSON MUST NOT contain trailing whitespace, comments, or extension keys. JSON field order follows serde serialisation of the declared Rust struct; implementations producing or consuming canonical JSON MUST use the field names and nesting shown here.
- Numeric fields use JSON numbers in their natural representation. `cutoff_days` is signed; negative values are valid for pre-1970 cutoffs.

Source citation: `provii-verifier/src/routes/verify.rs`, `PublicInputsJson` and `IssuerKeyJson`.

### 15.7 RP Challenge Bytes

`rp_challenge` is 32 bytes derived as `SHA-256(origin || nonce || "provii.challenge.v0")` at challenge-record creation time, where `nonce` is 32 bytes from the Verifier's CSPRNG (Section 13.2). The Verifier and the Wallet both compute `rp_hash = H_b2s(rp_challenge)` (Section 13.2); `rp_hash` is what flows into the circuit's public input vector at indices 2 and 3.

`rp_challenge` travels the wire as 32 raw bytes encoded with base64url-no-pad (43 characters).

### 15.8 PKCE Construction

```
code_verifier  = a 43 to 128 character URL safe string,
                 generated by the RP from a CSPRNG
code_challenge = base64url_no_pad(H_sha256(code_verifier_bytes))
                                              // 43 characters
```

The character set for `code_verifier` is the unreserved set from [RFC3986]: ALPHA / DIGIT / `-` / `.` / `_` / `~`. Implementations MUST conform to [RFC7636] Section 4.

### 15.9 CachedChallenge (Server Side)

This is the Verifier's internal challenge-record structure, not transmitted over the wire in this shape. It is documented here so conforming Verifier implementations agree on the field set. The reference implementation names the type `CachedChallenge`; earlier drafts of this specification named it `ChallengeRecord`.

```
CachedChallenge {
    id:                  String,          // UUIDv4, 36 chars, hyphenated
    rp_challenge:        [u8; 32],
    cutoff_days:         i32,
    verifying_key_id:    u32,
    code_challenge:      String,          // PKCE base64url_no_pad
    submit_secret:       [u8; 32],
    origin:              String,
    expires_at:          u64,             // Unix seconds
    proof_direction:     ProofDirection,  // OverAge | UnderAge, snake_case on wire
    state:               ChallengeState,  // see below
    short_code:          String,          // 12-digit numeric code (XXXX XXXX XXXX)
    status_url:          String,          // for Relying Party polling
    verify_url:          String,          // for Wallet short-code resolution
    created_at:          u64,             // Unix seconds
    client_id:           String,          // authenticating Relying Party
    result:              Option<bool>,    // Some(true|false) once verified
    failure_code:        Option<String>,  // error code on Failed state
    redeemed_at:         Option<u64>,     // Unix seconds of redemption
    proof_submitted_at:  Option<u64>,     // Unix seconds of submission
    ip_hash:             Option<String>,  // salted SHA-256 of submitter IP
    user_agent_hash:     Option<String>,  // salted SHA-256 of UA string
}
```

`ChallengeState` has five variants:

| State | Meaning |
|---|---|
| `Pending` | Challenge issued, no proof submitted yet |
| `ProofOkWaitingForRedeem` | Proof verified successfully, awaiting Relying Party redeem |
| `Verified` | Result delivered to Relying Party via redeem |
| `Failed` | Proof submission failed cryptographic verification |
| `Expired` | Challenge age exceeded `expires_at` with no terminal transition |

Implementations MAY add fields (for example, additional tracing identifiers) but MUST preserve the semantics of the listed fields and MUST NOT relax the five-state machine.

Source citation: `provii-verifier/src/cache.rs`, `CachedChallenge`.

### 15.10 Proof Submission Payload

The wallet submits a Groth16 age proof to the Verifier at `POST /v0/verify`. The shipping implementation uses the following two-level Rust declaration; serde serialises fields in declaration order.

```rust
struct SubmitProofRequest {
    challenge_id:    String,            // UUIDv4, 36 chars, hyphenated
    submit_secret:   [u8; 32],          // base64url no pad, 43 chars
    proof:           AgeProofJson,
}

struct AgeProofJson {
    verifying_key_id:  u32,
    public:            PublicInputsJson,  // Section 15.6
    proof:             [u8; 192],         // base64url no pad, 256 chars;
                                          // canonical Bellman serialisation
}
```

Wire encoding (JSON), keys in the serde declaration order above:

```json
{
    "challenge_id":   "c11e0ffe-f00d-4bad-9abc-123456789012",
    "submit_secret":  "BASE64URL32...",
    "proof": {
        "verifying_key_id": 914153247,
        "public": {
            "cutoff_days":    11246,
            "rp_challenge":   "BASE64URL32...",
            "issuer":         { "value": "BASE64URL32..." },
            "cred_nullifier": "BASE64URL32..."
        },
        "proof":         "BASE64URL_OF_192_BYTES..."
    }
}
```

JSON field order follows serde serialisation of the declared Rust structs; implementations producing or consuming canonical JSON MUST use the field names and nesting shown here. The inner field is `proof.proof` (the outer object's `proof` key names an `AgeProofJson` object which itself contains a `proof` byte field). Implementations MUST reject unknown keys (`#[serde(deny_unknown_fields)]` or equivalent) at every nesting level.

The submission MUST NOT include the direction; the Verifier retrieves it from its challenge record. The submission carries the raw `rp_challenge`; the Verifier wraps it to `rp_hash` independently (Section 13.2).

Source citation: `provii-verifier/src/routes/verify.rs`, `SubmitProofRequest` and `AgeProofJson`.

---

## 16. Conformance

### 16.1 Conformance Statement

An implementation that fully implements the requirements of this specification (including every MUST, MUST NOT, SHALL, SHALL NOT, REQUIRED and PROHIBITED requirement identified in this document) MAY claim "Provii v0.1 Compliant".

An implementation that implements a subset (e.g. only the Wallet role, only the Verifier role) MAY claim conformance to a specific profile defined below.

### 16.2 Profiles

Three profiles are defined. An implementation MAY conform to one or more profiles.

**Wallet Profile.** An implementation acting as a Provii Wallet MUST implement:
- Section 7 (Hash Function Specifications)
- Section 8 (RedJubjub Signature Scheme; verification at minimum, signing if it generates credentials)
- Section 9 (Pedersen Commitment Scheme; commit, validate, nullifier)
- Section 10.4 and 10.5 (Verify Attestation, Verify with Freshness)
- Section 11.4 (wallet steps 1, 3, 11, 12: generate `r_bits`, call blind issuance, verify the returned credential, persist to secure storage)
- Sections 11.7 and 11.8 (wallet secure storage; wallet issuer registry where supported; registry targets are SHOULD-level in v0.1)
- Section 12 (Age Verification Circuit; prover side)
- Section 13.4 to 13.6 (PKCE participation, Wallet preflight, public input assembly)
- Section 13.8 (Proving key download and integrity)
- Section 13.9 (Proof generation)
- Section 14.4 and 14.5 (Wallet side steps and proof submission)
- Section 15 wire formats it produces or consumes
- Section 17 security requirements applicable to wallet operation

**Verifier Profile.** An implementation acting as a Provii Verifier MUST implement:
- Section 7 (Hash Function Specifications)
- Section 9.4 (Nullifier; for ban enforcement)
- Section 12 (Age Verification Circuit; verifier side)
- Section 13.1, 13.2, 13.4, 13.6, 13.7, 13.10 (Groth16 parameters, RP hash construction, PKCE validation, public input assembly, VK identification, proof verification)
- Section 14.2, 14.6, 14.7, 14.9 (Challenge generation, verifier side steps, result redemption, replay protection and ban enforcement)
- Sections 15.6, 15.7, 15.9, 15.10 (public input JSON, RP challenge bytes, CachedChallenge, proof submission payload)
- Sections 17.5, 17.7, 17.8, 17.10, 17.13 (constant time operations, validation requirements, failure modes, algorithm agility, denial of service considerations)

A Verifier MAY additionally implement Section 8.6 (off-circuit RedJubjub verify) for issuer-registry validation at ingest; this is operationally useful but not required for conformance because the in-circuit signature check inside the Groth16 verification is authoritative.

**Issuer Profile.** An implementation acting as a Provii Issuer MUST implement:
- Section 7 (Hash Function Specifications)
- Section 8 (RedJubjub Signature Scheme; full sign and self-verify)
- Section 9 (Pedersen Commitment Scheme; commit, validate)
- Section 10 (Ed25519 Attestation Scheme; create per Section 10.3 and self-verify per Section 10.4)
- Section 11 (Issuance Protocol; all steps the Issuer performs)
- Sections 11.6 and 11.7 (audit log retention at issuance; Wallet Storage expectations)
- Section 15 wire formats it produces or consumes
- Section 17 security requirements applicable to issuance operation

A Relying Party is not a profile in this specification because the RP's interaction with the protocol is API mediated (challenge request, result redemption); no cryptographic conformance is required of the RP beyond basic PKCE behaviour ([RFC7636]) and proper handling of the verification result.

### 16.3 Mandatory Features

Any conforming implementation MUST implement:

- All algorithms in Sections 7, 8, 9 that fall under its profile.
- All system constants in Section 6 with the values specified.
- All domain separation tags in Section 5.1 (active DSTs).
- The wire formats in Section 15 for messages it produces or consumes.
- The constant time comparison requirements in Section 17.5.
- The memory hygiene requirements in Section 17.6 (zeroisation of signing keys, witness material, and DOB / randomness across drop boundaries).

Additional conformance prohibitions:

- A conforming Wallet MUST NOT transmit, log, derive a non-cryptographic identifier from, or otherwise expose `dob_days` or `r_bits` to any party post-issuance. This prohibition covers analytics SDKs, crash reporters, advertising identifiers, embedded third-party SDKs, and any other channel that would move these values outside the secure-storage boundary established in Section 11.4. The only exception is the proof generation path defined in Section 13, which consumes both values as private witnesses and MUST NOT emit them.
- A conforming Verifier MUST NOT retain proof bytes after verification completes, unsalted IP addresses, browser fingerprints, TLS fingerprints, or any correlation of nullifiers with a persistent identifier of the submitting client. Hashed IP retention is permitted only under the salted-SHA-256 construction in Section 18.4; raw IP retention is a privacy regression regardless of the log store.

### 16.4 Optional Features

The following features are optional. Implementations MAY support them. Implementations that do not support them MUST nevertheless preserve interoperability with implementations that do.

Credential expiry enforcement is wallet-side in v0.1. The Wallet preflight check (Section 13.5) is normative. The Verifier does not receive `iat` or `exp` and CANNOT enforce expiry in v0.1 (Section 12.9, Section 14.6 step 10h). This is a deliberate scoping decision; see Section 17.11 for the trust assumption.

Site-key-bound challenge signatures and issuance consent signatures are deferred to a future protocol version; see the "Deferred to Future Versions" appendix.

The RP-bound RedJubjub signing variant (`SignWithRP`) present in some implementations is **NOT** part of v0.1. Implementations MUST NOT consume RP bound signatures in v0.1; a future protocol version may revive this construction.

### 16.5 Conformance Tests

Implementations claiming conformance MUST pass every normative test vector in Appendix A. Failure to reproduce a normative test vector is non-conformance.

Implementations claiming conformance SHOULD execute the worked examples in Appendix B as integration tests.

---

## 17. Security Considerations

This section provides a security analysis of the Provii protocol. It is not a feature list. It identifies the threat model, the assumptions on which protocol security depends, the parameter justifications, and known failure modes.

### 17.1 Threat Model

The following adversaries are considered.

**Malicious Wallet.** A wallet user who attempts to prove an age threshold their date of birth does not satisfy. The wallet may have full control over its device, may modify the wallet code, and may introspect any state.

Defence: the wallet cannot produce a credential signed by an authorised Issuer for any date of birth other than the one the Issuer attested to (Section 11). The age verification circuit (Section 12) cryptographically binds the proof to a credential opening that satisfies the predicate; a malicious wallet cannot construct a valid proof for an unsatisfied predicate without solving the discrete log problem on Jubjub.

**Malicious Verifier.** A verifier server operator (in this protocol, the Provii-operated Verifier; there is only one) who attempts to extract identifying information about Wallet users from the proofs verified.

Defence: the proof is zero knowledge per the Groth16 construction (see [Groth16] and the Pinocchio / Groth construction's simulation-soundness argument); it leaks nothing about the witness beyond the truth of the predicate. The public inputs to the proof contain no personal identifiers. The Verifier learns the nullifier and uses it for replay detection against its ban store; it learns no name, no document, no date of birth.

**Malicious Relying Party.** A Relying Party that attempts to extract more information than the binary verification result.

Defence: the response returned to the Relying Party at redemption is the binary verification outcome only. The Relying Party knows the cutoff it requested and the `proof_direction` the Verifier derived for its registered origin, both by construction of the challenge; the Verifier does not return proofs, public inputs, or nullifiers to the Relying Party.

**Malicious Issuing Party.** An Issuing Party that attempts to obtain attestations for fraudulent dates of birth.

Defence: the protocol does not defend against a compromised Issuing Party directly. An Issuing Party is, by definition, trusted by the Issuer to present DOBs it has verified via its own KYC systems. The Issuer maintains a per-Issuing-Party HMAC-SHA256 client secret (Section 11.2) and logs every attestation against the authenticating `CLIENT_ID`; the Issuer MAY suspend a misbehaving Issuing Party by revoking its client secret. Compromise of an individual Issuing Party is detected and remediated operationally, not cryptographically.

**Network Attacker.** An attacker on the wire between any pair of parties.

Defence: TLS 1.3 protects the wire. The cryptographic protocol additionally binds proofs to specific challenges via the `rp_hash` public input (Section 13.2), so even an attacker who reads the proof cannot replay it against a different challenge.

### 17.2 Cryptographic Assumptions

Provii's security depends on the following cryptographic assumptions.

1. **Discrete log on Jubjub.** Computing `sk` from `[sk] G` is computationally infeasible. This underlies RedJubjub signature unforgeability and Pedersen commitment binding.
2. **Discrete log on BLS12-381.** Underlies Groth16 soundness.
3. **Pairing assumptions on BLS12-381.** Specifically, the asymmetric pairing-related assumptions Groth16 reduces to (q-PKE, GAP-CDH).
4. **Random oracle behaviour of Blake2s-256, SHA-256, and the Sapling Pedersen hash.** Used in the security proofs of the signature scheme, commitment, and circuit constructions.
5. **Trusted setup integrity.** The Groth16 trusted setup MUST have been performed via an MPC ceremony with at least one honest participant, and the toxic waste of every participant MUST have been destroyed. If toxic waste survives in any participant's hands, that participant can forge proofs.
6. **Ed25519 unforgeability.** Used for the issuer attestation. Standard EdDSA assumption.

If any of these assumptions falls (for example, a quantum computer breaking discrete log), the protocol's security falls. See Appendix D for the post quantum migration trajectory.

### 17.3 Trust Setup Integrity

The Groth16 proving and verifying keys for the v0.1 age circuit are produced by a trusted setup ceremony [Zcash]. The integrity of the parameters depends on the trustworthiness of the ceremony.

Implementations MUST verify the proving key and verifying key against the manifest values listed in Section 13.7 before relying on them.

The provenance of the v0.1 deployed parameters is a deployment-operator question and is intentionally NOT pinned in this protocol document. Until the operator publishes a ceremony transcript (participants, dates, process, contribution hashes, transcript locations), implementations SHOULD treat the deployed parameters as trusted only to the extent that the operator of the deployed environment is trusted.

### 17.4 Issuer Key Management

The Issuer holds two long lived keys: an Ed25519 attestation signing key and a RedJubjub credential signing key.

The Issuer MUST rotate both keys periodically. The recommended rotation cadence is 180 days. After rotation:

- The old `kid` MUST remain in the Verifier's issuer registry until all credentials issued under the old `kid` have expired.
- New credentials MUST be signed under the new `kid`.

The Issuer MUST publish its active RedJubjub verifying keys to the Verifier's issuer registry. The publication mechanism is operational (a JWKS-style HTTP endpoint over TLS is the typical implementation).

If an Issuer key is compromised, the Issuer MUST remove the key from the registry immediately. v0.1 does not standardise a real-time notification channel between Issuer and Verifier for compromise events; see Section 17.15 for the operational procedure.

### 17.5 Constant Time Operations

The following operations MUST be constant time with respect to secret material:

| Operation | Required because |
|---|---|
| Comparison of `submit_secret` (Verifier side, Section 14.6 step 10b) | Submit secret is a 32 byte authenticator; timing leak enables forgery |
| Comparison of `rp_challenge` (Verifier side, Section 14.6 step 10c) | Although `rp_challenge` is publicly known to the wallet, the Verifier compares against its stored value; constant time is defence in depth |
| Comparison of PKCE `code_verifier` hash against `code_challenge` (Section 14.7) | Code verifier is a secret known only to the Relying Party |
| Comparison of RedJubjub signature verification result (`s G == R + c VK`, Section 8.6) | Avoids leaking which intermediate equality failed |
| Ed25519 verification | Per [RFC8032] guidance |
| HMAC verification for Issuer authentication (Section 11.2) and Expert Verifier authentication (Section 14.2) | Standard HMAC guidance |
| RedJubjub signing (the scalar arithmetic that produces `s = nonce + c sk`) | The signing key `sk` is secret |

Implementations MUST use one of the following platform primitives for every constant-time comparison of secret material. No hand-rolled implementation is permitted.

| Language / platform | Required primitive |
|---|---|
| Rust | `subtle::ConstantTimeEq::ct_eq()` or `hmac::Mac::verify_slice()` |
| TypeScript on Cloudflare Workers | `crypto.subtle.timingSafeEqual()` |
| TypeScript on Node.js | `crypto.timingSafeEqual()` |
| Swift (iOS) | `constantTimeCompare()` in the wallet's Core/Security module |
| Kotlin (Android) | Delegated to Rust via UniFFI |

Implementations MUST NOT use language level `==` on secret bytes.

Implementations MUST NOT branch on secret values. Implementations MUST NOT index arrays with secret values.

The Groth16 prover and verifier as implemented in Bellman are not formally verified to be constant time. This is a known limitation. Section 12.3 of [Groth16] describes the algorithm; implementations following standard practice are not known to leak via timing in ways exploitable in the Provii deployment model, but this has not been formally proven.

### 17.6 Memory Hygiene

The following data MUST be zeroised on drop or scope exit:
- RedJubjub signing keys (`SigningKey`)
- Ed25519 signing keys (`AttestationKey`)
- Wallet state holding `dob_days` and `r_bits`
- Witness data passed to the Groth16 prover
- Any intermediate scalar values in signing or signature verification

Implementations MUST use the `zeroize` crate (Rust) or equivalent. Implementations MUST NOT log, debug print, or serialise secret values outside of platform secure storage.

The `Debug` derivations on types containing secret material MUST redact those fields. The conforming behaviour is to print `[REDACTED]` in place of the value.

### 17.7 Validation Requirements

Implementations MUST validate inputs at trust boundaries. The following table lists validation points.

| Function | Validation |
|---|---|
| `cred_v2_prehash_bytes` | `len(kid) <= 255`, `len(schema) <= 255` |
| `AgeWitness::new` | `len(kid) == 14`, `len(schema) == 12`, `len(sig) == 64`, `len(r_bits) == 128` |
| `validate_commitment_randomness` | `128 <= len(r_bits) <= 1096`, ≥ 8 unique byte values, not all zero |
| `SigningKey::from_bytes` | canonical scalar, non zero, in canonical range of `Fr_J` |
| `VerificationKey::from_bytes` | in prime order subgroup, not identity, not small order |
| `Signature::from_bytes` | `R` in subgroup, `s` canonical |
| `validate_nonce` | length 32, ≥ 8 distinct bytes, not all zero |
| `Attestation::verify_with_timestamp` | `timestamp >= now - 3600`, `timestamp <= now + 60` |
| `verifier::verify_age_snark` | `vk_id` registered, proof byte length validates, public inputs assemble |

Validation failures MUST return errors. Implementations MUST NOT panic, abort, or coerce invalid inputs.

### 17.8 Failure Modes

The following failure modes are part of the protocol's failure surface. The Verifier reports them as `ApiError::BadRequest` with the indicated machine-readable code in the response body. The Issuer reports issuance failures analogously through its own error envelope.

| Failure | Code |
|---|---|
| Proof bytes do not parse | `INVALID_PROOF_ENCODING` |
| Proof verifies to false | `INVALID_PROOF` |
| Submit secret mismatch | `INVALID_SUBMIT_SECRET` |
| RP challenge mismatch | `INVALID_CHALLENGE` |
| Nullifier on ban list | `CREDENTIAL_BANNED` |
| Challenge expired | `CHALLENGE_EXPIRED` |
| Challenge already consumed | `CHALLENGE_ALREADY_CONSUMED` |
| Challenge not found | `CHALLENGE_NOT_FOUND` |
| `verifying_key_id` not in registry | `UNKNOWN_VERIFYING_KEY` |
| Issuer not in registry | `UNKNOWN_ISSUER` |
| Attestation expired | `ATTESTATION_EXPIRED` |
| Attestation signature invalid | `INVALID_ATTESTATION_SIGNATURE` |
| Attestation nonce reused | `NONCE_REUSE` |

The Verifier MUST NOT reveal which check failed in its externally visible response beyond the code above, unless the failure is operationally useful to the Relying Party and the Relying Party is trusted to receive that information. Errors visible to Wallets SHOULD be mapped to a small set of categories (validation error, authentication error, server error) to prevent oracle attacks.

### 17.9 Side Channels

The protocol has not been formally analysed for side channel resistance beyond the constant time requirements in Section 17.5. Implementations on platforms with shared caches, branch predictors, or other microarchitectural state SHOULD consider deploying additional countermeasures appropriate to their deployment.

The Blake2s and SHA-256 implementations used (`blake2s_simd`, `sha2`) are not formally verified to be constant time. They are widely used in cryptographic deployments without known timing exploits.

The Pedersen hash via `sapling_crypto` operates on bit decompositions; it is not known to leak timing information for inputs of fixed length.

### 17.10 Algorithm Agility

The protocol incorporates explicit version identifiers at every layer: credential version `v`, circuit constants version (`v0`), `vk_id`. These enable migration to new cryptographic algorithms without breaking existing credentials.

Implementations MUST embed `vk_id` in every proof submission so the Verifier can route to the correct verifying key. Implementations MUST verify the circuit constants hash matches the implementation's expected value before relying on the proving or verifying key.

The protocol is forward compatible with the introduction of new `vk_id` values. Verifiers MAY support multiple `vk_id` values simultaneously; old `vk_id` values SHOULD be retired only after all credentials issued against them have expired.

Per the project policy "no migration code", old `vk_id` values are retired by removal from the registry rather than maintained for backward compatibility. Wallets that have not refreshed their proving key MUST detect the retirement (their proofs are rejected with `UnknownVerifyingKey`) and MUST refresh.

### 17.11 Expiry Trust Assumption

v0.1 relies on wallet-side enforcement of credential expiry. The Verifier does not receive `iat` or `exp`; they are inside the witness and never cross the wire. A malicious Wallet that skips preflight (Section 13.5) can present an expired credential and obtain a successful verification. The protocol does not defend against this failure mode at the Verifier.

Relying Parties and Verifier operators that require stronger guarantees of expiry enforcement MAY require their Issuers to issue credentials with shorter validity periods; the window of misuse by a malicious Wallet is bounded by the credential lifetime. This is a deliberate departure from the default posture (Section 17.12) that credentials age with the user, and SHOULD be justified against documented operational needs rather than adopted by default.

A future protocol revision may add `iat` or `exp` to the public input set, pushing the check into the circuit at the cost of two additional multipacked field elements and the associated trusted setup change. v0.1 consciously trades server-side expiry enforcement for smaller submission payload and simpler verifier state.

### 17.12 Credential Lifetime Recommendations

Issuers SHOULD set credential lifetimes (`exp - iat`) long enough that the credential ages with the user. The RECOMMENDED default for general deployments is 7 300 days (20 years), which carries a credential issued in childhood through into adulthood without a re-issuance ritual. The hard ceiling enforced by `MAX_VALIDITY_SECONDS` (Section 6) is 36 500 days (approximately 100 years).

The underlying identity fact is stable: a user's date of birth does not change, and re-issuance for its own sake degrades user experience without strengthening the privacy or integrity guarantees of the protocol. The wallet enforces expiry locally (Section 17.11) and a malicious wallet that skips preflight is the adversary bounded by lifetime, not the typical user.

Deployments that need a tighter expiry-enforcement envelope, for example to bound the window of misuse following a compromise disclosed outside the protocol, MAY issue shorter-lived credentials at the cost of more frequent issuance round trips. This is an explicit departure from the default posture and SHOULD be documented against operational needs.

### 17.13 Denial of Service Considerations

The protocol does not mandate rate limits but operators MUST consider the following vectors.

**Challenge creation.** An attacker may attempt to exhaust Verifier storage by issuing many challenge requests. Operators SHOULD rate-limit challenge creation per-origin and per-source-IP. A typical budget is on the order of 10 to 50 requests per minute per source before throttling.

**Proof submission.** Proof verification is comparatively expensive (single-digit milliseconds to tens of milliseconds for a Groth16 verify over BLS12-381). The Verifier MUST enforce the following ordering so cheap checks run before expensive ones:

```
Step 1. challenge_id lookup                      // O(1) map lookup
Step 2. submit_secret constant-time cmp          // O(1) 32-byte compare
Step 3. rp_challenge constant-time cmp           // O(1) 32-byte compare
Step 4. nullifier ban-store lookup               // O(1) map lookup
Step 5. issuer registry lookup                   // O(1) map lookup
Step 6. verifying_key_id registry lookup         // O(1) map lookup
Step 7. Groth16 verify_proof                     // expensive
```

A submission that fails any of steps 1 through 6 MUST NOT proceed to step 7.

**Wallet-side prover DoS.** A malicious Relying Party may issue many challenges to coerce a Wallet into repeated proof generation. Wallets MUST limit the rate at which they accept new challenges from any single origin and MUST require fresh user consent for each proof generation.

**Proving key CDN.** Wallets MUST download the proving key over TLS. CDNs serving the proving key MUST NOT share download metadata with third parties beyond what is strictly required to serve the bytes.

### 17.14 Fault Injection

The protocol does not defend against physical fault attacks on the prover (electromagnetic glitching, voltage glitching, laser fault injection). An attacker with physical access to a Wallet can coerce the Groth16 prover into emitting a proof for constraints that the witness does not satisfy.

Wallet implementations SHOULD rely on platform secure enclaves or TrustZone-backed key storage for the credential signing operation where available. Wallet implementations MUST verify the witness constraints immediately after proof generation by running the verifier locally before submission. A post-prover local verify catches non-malicious prover bugs and raises the cost of a fault attack by requiring the attacker to corrupt both prover and verifier simultaneously.

### 17.15 Issuer Revocation

v0.1 does not standardise an issuer revocation channel between the Issuer and the Verifier. A compromised signing key is removed from the Verifier's allowlist by direct operator action on the Verifier's issuer registry. Deployment operators MUST document their revocation procedure and its expected propagation latency to Relying Parties.

### 17.16 RedJubjub Key Reuse Prohibition

A RedJubjub signing key used in Provii MUST NOT be used in any other protocol. Nonce derivation (Section 8.3) is deterministic from `sk` and the message hash. If a key is used in two protocols whose messages can collide or whose message encodings overlap, two different signatures under the same nonce may be produced. Two signatures under the same nonce permit recovery of the signing key.

Protocol designers considering reuse MUST prove that their message encodings are domain-separated from Provii's and that no input can produce the same 32-byte `msg_hash` across the two protocols. The simpler and normative rule is: do not reuse the key.

### 17.17 Defensive Checks on RedJubjub Inputs

Implementations MUST reject:

- A zero nonce scalar at any point in Sign. If the nonce reduction in Section 8.3 yields zero, the implementation MUST resample (by perturbing the input with a single retry counter byte or aborting with an error). The probability of a zero nonce from a correctly seeded CSPRNG is negligible; any occurrence indicates a defect.
- An identity verifying key at Verify. A VK equal to the identity point represents a zero signing scalar and MUST be rejected at deserialisation (Section 8.1) and at verification (Section 8.6).

### 17.18 DOB Range Sanity Check

The Issuer MUST reject `dob_days` values outside the operationally plausible range (normative; see §10.2). The range is `[-36525, +36525]`, spanning approximately ±100 years from the Unix epoch. Values outside this range almost always indicate a data-entry error upstream at the Issuing Party's KYC system. The Ed25519 attestation field remains an `i32` internally; the MUST applies at the issuance boundary.

### 17.19 `vk_id` Collision Bound

`vk_id` is a 32-bit identifier (Section 13.7). The birthday bound predicts a collision at approximately 2^16 distinct keys. Deployments that rotate verifying keys infrequently are unaffected. Deployments that cycle fewer than 256 verifying keys concurrently or retain history below 4096 keys are well below the birthday bound. A future protocol revision may widen `vk_id` to `u64` when deployment density warrants it.

---

## 18. Privacy Considerations

### 18.1 Information Each Party Learns

The following table summarises information learned by each party under correct operation.

| Party | Learns | Does NOT learn / send / store |
|---|---|---|
| Wallet | Nothing about the Verifier or Relying Party beyond what the user observed when scanning a QR code or following a deep link. Sends to the Verifier: the Groth16 proof (zero knowledge), the `cutoff_days` public input, the `rp_challenge`, the `issuer_vk`, and the `cred_nullifier`. | Does NOT send date of birth, name, document number, identity, or Wallet identifier. |
| Issuing Party | User's date of birth (from its own KYC systems), the `CLIENT_ID` it uses to authenticate, and the attestation bytes it relays to the Wallet via deep link. Retains the DOB in its own KYC record per its regulatory obligations. | Does NOT see the credential, the commitment, the randomness, the nullifier, or the proof. Holds no Provii signing keys. |
| Issuer | During issuance: the Issuing Party's `CLIENT_ID`, the DOB supplied in the authenticated request, and the commitment randomness from the Wallet. Discards DOB and `r_bits` immediately after Step 10 of Section 11.4. Retains issuance audit metadata per Section 11.6. | Does NOT retain DOB, `r_bits`, or the resulting commitment. |
| Verifier | That a verification occurred, the binary result, the credential nullifier (used to check the ban store), the issuer verifying key, the Relying Party origin, and the `cutoff_days`. Stores salted-SHA-256 pseudonyms of IP addresses (see Section 18.5), challenge records for up to `CHALLENGE_EXPIRY_SECONDS`, a nullifier ban store (managed by operator action; see Section 14.9), and verification-event audit log entries (90 day retention). | Does NOT learn the user's date of birth, the credential's `iat`/`exp` (inside the witness), the user's name, or the user's wallet identity. |
| Relying Party | The binary verification result. Knows the `cutoff_days` it itself sent in the challenge request and the `proof_direction` the Verifier derived for its registered origin. | Does NOT learn the proof, the public inputs, the user's age, the user's date of birth, the user's wallet identity, or the nullifier. |

Total personal data in the verification flow is limited to salted-SHA-256 pseudonyms of IP addresses (in Verifier logs, with limited retention; see Section 18.4). Total age related data in the verification flow is zero. The age threshold is set by the Relying Party and is public; the user's actual age is never revealed.

### 18.2 Unlinkability

Two proofs generated by the same Wallet against the same Credential are unlinkable to an observer who does not have access to the Verifier's nullifier log. The proof bytes differ across presentations because Groth16 is zero-knowledge; the public inputs are identical for the static parts (`issuer_vk`, `cred_nullifier`) and differ in the per-challenge parts (`rp_challenge`, `cutoff_days`, `proof_direction`).

The mechanisms supporting unlinkability are:

- No persistent user identifier appears in the protocol; users have no accounts at the Verifier.
- Each verification request carries a fresh 32 byte `rp_challenge` derived by the Verifier from a CSPRNG nonce and the origin (Section 13.2).
- The proof is zero knowledge; the proof bytes do not depend on the user identity in any way that can be reconstructed.
- The Verifier's nullifier enables credential banning but is not linked to the user identity.
- The Verifier API is stateless from the Wallet's perspective; each submission is independent.

### 18.3 Linkability at the Verifier

Multiple proofs generated by the same Wallet from the same Credential, submitted to the Verifier, present the same nullifier. The Verifier uses this property to recognise repeat verifications from the same credential; this is intentional and supports the nullifier ban store described in Section 14.9. Nullifier equality does not link verifications to user identity: the Verifier never learns the user's name, DOB, or any external identifier that would map a nullifier back to a real-world subject.

Within the scope of this specification, a user seeking to present an unlinkable verification would need a second credential with a distinct commitment and therefore a distinct nullifier. v0.1 supports one Credential per Wallet.

### 18.4 Side Channel Privacy

Beyond cryptographic protocol leaks, the following operational data points are unavoidable:

- **Network metadata.** Connection timing, source IP address, and browser fingerprint when the Relying Party is web based. The Verifier MUST store IP addresses only as `SHA-256(ip || salt)` where `salt` is a per-deployment secret rotated at least daily and destroyed on rotation. A plain unkeyed `SHA-256(ip)` MUST NOT be used because the IPv4 address space (2^32 entries) is trivially brute-forceable against an unsalted hash. Raw IP retention beyond the life of the request is a privacy regression.
- **Timing of verification request.** The Verifier can correlate the time of a verification request with other observable user activity if it has access to such data. Verifier operators MUST minimise such correlation surfaces in their operational telemetry.
- **Origin string.** The Verifier sees the Relying Party origin on every challenge creation. A Relying Party that uses different origins for different user cohorts can leak cohort membership; this is an application-layer concern rather than a protocol-layer concern.
- **Timing of proof generation.** A Wallet that generates proofs on a shared device could leak the start and end times of proof generation through CPU or GPU activity metrics visible to other processes. Platform sandboxing provides adequate defence on modern mobile operating systems.

Implementations MUST apply the principle of data minimisation throughout the deployment and MUST retain no operational metadata beyond the retention windows defined in Section 18.7.

### 18.5 Ed25519 Attestation Privacy

The Ed25519 attestation contains the date of birth in cleartext. It is a privacy sensitive object during transit between the Issuing Party and the Issuer, and during transit between the Issuing Party and the Wallet via deep link.

Implementations MUST transport attestations only over TLS 1.3 or later (Issuing Party to Issuer) or via the platform deep-link mechanism (Issuing Party to Wallet), which is secured by the host operating system's inter-app messaging model. Wallets SHOULD discard the attestation immediately after the Issuer returns a SignedCredential; there is no protocol need to retain it.

The Ed25519 attestation nonce, a 32 byte CSPRNG value, is covered by the Issuer's single-use nonce store (Section 10.6). Reuse beyond that window is a security issue, not a privacy issue.

### 18.6 Audit Log Privacy

Audit logs at the Issuer (Section 11.6) MUST NOT contain `dob_days`, `r_bits`, or the commitment. They MAY contain the Issuing Party's `CLIENT_ID`, key identifier, schema identifier, and timestamps.

Audit logs at the Verifier MUST NOT contain Wallet-identifying information beyond what the Verifier has by other operational means (origin, salted-SHA-256 IP pseudonym per Section 18.4). Verification-event logs MAY contain the nullifier (for ban-store auditing) and the verification result.

### 18.7 Audit Log Retention

The recommended audit log retention period for both the Issuer and the Verifier is 90 days. The 90 day ceiling balances four independent constraints:

| Constraint | Effect on the 90 day ceiling |
|---|---|
| Regulatory minimums | Typical regulatory guidance for security-event retention (for example, Australian guidance for operational logs and analogous European requirements) sets a floor that 90 days comfortably exceeds. |
| Maximum credential lifetime | Section 17.12 recommends 20 year credential lifetimes so the credential ages with the user; audit logs of issuance events need not span the full credential life, and 90 days is sufficient to support incident response and retrospective review of recent issuance activity. |
| Residual privacy exposure | Long-lived records risk later correlation with external datasets; shorter retention reduces that exposure. |
| Operational cost | Storing and indexing audit volumes over extended windows is expensive; 90 days is a practical ceiling for typical deployment budgets. |

Normative requirements:

1. The Issuer and the Verifier MUST NOT retain audit log entries beyond 90 days unless a longer period is required by applicable regulation. Where regulation mandates longer retention, the extended portion MUST be segregated from the default 90 day tier and MUST carry an explicit legal-basis marker.
2. Where regulation permits shorter retention, implementations SHOULD adopt the shortest practicable period consistent with incident investigation needs. A retention floor below 30 days is NOT RECOMMENDED unless an incident-response process with equivalent forensic guarantees is in place.
3. Deletion at the retention boundary MUST be complete: no shadow copies, no indices, no backups retained past the retention boundary (backup rotation cycles MAY be used as the deletion mechanism provided the full cycle completes within the retention window).
4. Pseudonymous identifiers in audit logs (for example, salted-SHA-256 IP pseudonyms per Section 18.4, nullifiers) are in scope for retention limits and MUST be deleted on the same schedule as the records that contain them. The Verifier's nullifier ban store (Section 14.9) is scoped separately by operator policy: ban entries are not audit log entries and persist until operator action removes them.
5. A conforming deployment MUST publish its audit retention policy as part of its operator documentation, including the retention duration, the legal basis for any extensions beyond 90 days, and the deletion mechanism.

---

## 19. IANA Considerations

This document has no IANA actions. Should a future revision of this specification require registration of media types, URN schemes, OID arcs, or other IANA-managed values, those registrations are specified in the revision.

---

## 20. References

### 20.1 Normative References

[RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997, `https://www.rfc-editor.org/info/rfc2119`.

[RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017, `https://www.rfc-editor.org/info/rfc8174`.

[RFC7636] Sakimura, N., Bradley, J., and N. Agarwal, "Proof Key for Code Exchange by OAuth Public Clients", RFC 7636, September 2015, `https://www.rfc-editor.org/info/rfc7636`.

[RFC7693] Saarinen, M-J. and J-P. Aumasson, "The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)", RFC 7693, November 2015, `https://www.rfc-editor.org/info/rfc7693`.

[RFC8032] Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017, `https://www.rfc-editor.org/info/rfc8032`.

[RFC3986] Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax", STD 66, RFC 3986, January 2005, `https://www.rfc-editor.org/info/rfc3986`. Defines the unreserved character set referenced by PKCE (Section 13.4 and Section 15.8) and the URI syntax used for origin strings (Section 13.2).

[RFC9562] Davis, K., Peabody, B., and P. Leach, "Universally Unique IDentifiers (UUIDs)", RFC 9562, May 2024, `https://www.rfc-editor.org/info/rfc9562`. Defines UUID version 4 and the 36 character canonical hyphenated representation used for `challenge_id` in Section 14.2.

[PairingCurves] Sakemi, Y., Kobayashi, T., Saito, T., and R. Wahby, "Pairing-Friendly Curves", Work in Progress, Internet-Draft, draft-irtf-cfrg-pairing-friendly-curves-11, `https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/11/`. Authoritative BLS12-381 parameters, compressed point encoding, and subgroup membership conventions. Pinned at draft -11; this reference is updated when the draft is published as an RFC.

[ZcashSapling] Hopwood, D., Bowe, S., Hornby, T., and N. Wilcox, "Zcash Protocol Specification, Version 2024.5.4 [NU6]", The Electric Coin Company, 2024, `https://zips.z.cash/protocol/protocol.pdf`. Specifically Section 5.4.1.7 (Pedersen hashes over the Jubjub curve), Section 4.2.2 together with Section 5.4.8.3 (Sapling spending key base point), and Section 5.4.7 (RedJubjub).

[Groth16] Groth, J., "On the Size of Pairing-Based Non-interactive Arguments", EUROCRYPT 2016, LNCS 9666, pp. 305-326, May 2016, `https://eprint.iacr.org/2016/260`.

[FIPS180-4] National Institute of Standards and Technology, "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015, `https://doi.org/10.6028/NIST.FIPS.180-4`.

[Bellman] Zcash, "bellman: A pure-Rust implementation of Groth16 zk-SNARKs", version 0.14, `https://github.com/zkcrypto/bellman`. Reference Groth16 implementation underlying Provii; the canonical proof and verifying key serialisations referenced in Sections 15.5 and 15.7 are defined by `bellman 0.14`.

[RFC4648] Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648, October 2006, `https://www.rfc-editor.org/info/rfc4648`. Section 3.5 defines the canonical decoding rule requiring rejection of encodings with non-zero trailing bits.

### 20.2 Informative References

[RFC6979] Pornin, T., "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)", RFC 6979, August 2013, `https://www.rfc-editor.org/info/rfc6979`. Conceptual reference for deterministic nonce derivation; Provii's RedJubjub nonce derivation differs in primitive choice (Blake2s instead of HMAC-SHA-256) and field (Jubjub scalar instead of EC-DSA).

[Zcash] Bowe, S., Gabizon, A., and I. Miers, "Scalable Multi-party Computation for zk-SNARK Parameters in the Random Beacon Model", IACR ePrint 2017/1050, 2017, `https://eprint.iacr.org/2017/1050`. Background on multi-party trusted setup ceremonies relevant to Section 17.3.

[Pedersen1991] Pedersen, T. P., "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing", CRYPTO 1991, LNCS 576, pp. 129-140, Springer, 1992, `https://link.springer.com/chapter/10.1007/3-540-46766-1_9`. The original Pedersen commitment construction used (in its curve-based form) for the commitment and nullifier defined in Section 9.

[ISO18013-5] ISO/IEC 18013-5:2021, "Personal identification, ISO-compliant driving licence, Part 5: Mobile driving licence (mDL) application", International Organization for Standardization, 2021. Related standard for mobile driving licence age verification; Provii targets a different deployment model.

[W3CVC] Sporny, M., Longley, D., and D. Chadwick, "Verifiable Credentials Data Model v2.0", W3C Recommendation, 15 May 2025, `https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/`. Related verifiable credentials standard; Provii's credential format is purpose specific.

---

## Appendix A: Test Vectors

This appendix contains normative test vectors. A conforming implementation MUST reproduce these byte sequences exactly given the listed inputs. Implementations that fail to reproduce a vector are non-conforming.

Hex encodings throughout this appendix are lower case ASCII hex with no separators, two characters per byte.

Canonical source: the deterministic test harness at `provii-crypto/crypto-e2e-tests/tests/spec_vectors.rs` materialises every value in this appendix from `ChaCha20Rng::from_seed([0u8; 32])` and asserts each byte. Run with `cargo test --release -p provii-crypto-e2e-tests --test spec_vectors -- --nocapture`. Drift between this appendix and the harness output is a defect.

### A.1 Bias Transformation

`bias_for_circuit(x: i32) -> u32 = (x as u32) XOR 0x8000_0000`.

| Input `dob_days` | `bias_for_circuit` (decimal) | `bias_for_circuit` (hex) |
|---|---|---|
| `-3653` | `2147479995` | `0x7fffe3bb` |
| `-1` | `2147483647` | `0x7fffffff` |
| `0` | `2147483648` | `0x80000000` |
| `1` | `2147483649` | `0x80000001` |
| `11246` | `2147494894` | `0x80002bee` |
| `13880` | `2147497528` | `0x80003638` |
| `i32::MAX` (`2147483647`) | `4294967295` | `0xffffffff` |
| `i32::MIN` (`-2147483648`) | `0` | `0x00000000` |

These values demonstrate the order preservation: `bias(-3653) < bias(-1) < bias(0) < bias(1)` when compared as unsigned 32 bit integers.

### A.2 Spending Key Generator

The Sapling spending key generator on Jubjub.

```
SPENDING_KEY_GENERATOR (32 bytes, hex):
30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a157
```

This is the canonical compressed Jubjub point encoding. It MUST decode to a prime order subgroup point.

### A.3 PKCE S256 KAT

From [RFC7636] Appendix B.

```
code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                 (43 ASCII characters)
code_challenge = base64url_no_pad(SHA-256(code_verifier))
               = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
                 (43 ASCII characters)
```

### A.4 Blake2s-256 Known Answer Tests

From [RFC7693].

```
H_b2s(b"") = 69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9

H_b2s(b"abc") = 508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982
```

### A.5 RP Challenge KAT

`rp_challenge` is derived by the Verifier as `SHA-256(origin || nonce || "provii.challenge.v0")` where the nonce is 32 bytes from a CSPRNG (Section 13.2).

```
Inputs:
    origin = "https://example.com"
    nonce  = 0x2a × 32                               // 32 bytes of 0x2a
    DST    = "provii.challenge.v0"

Preimage: origin || nonce || DST (70 bytes total).

rp_challenge = SHA-256(preimage)
             = 35dcc5ea16a967de4891a10c283e33ca9d0f29ba4ae02fcf70e49ba98175b9fa
```

### A.6 RP Hash KAT

`rp_hash` is the Blake2s-256 wrap of `rp_challenge`:

```
Input:
    rp_challenge = 35dcc5ea16a967de4891a10c283e33ca9d0f29ba4ae02fcf70e49ba98175b9fa

Construction:
    rp_hash = Blake2s-256(rp_challenge)              // no personalisation

Output:
    rp_hash = afe7e76cb0ac79e7157fcc7f4c5eb319daa0c106093794a1bbd00b4c85ff430e
```

### A.7 Pedersen Commitment KAT: Age 25

```
Inputs:
    dob_days  = 11246                      // i32
    dob_iso   = "2000-10-16"               // informational
    bias      = bias_for_circuit(11246) = 0x80002bee
    r_bits    = generate_commitment_randomness(
                  ChaCha20Rng::from_seed([0x07; 32]), 128)

Packed r_bits (LE, 16 bytes):
    f400927857aaf64114f561baacb37970

Output:
    commitment_hex = e437495ee5c2872cb408674c213b95f6efd086fda4687997a35321f0ad2d79aa
```

### A.8 Pedersen Commitment KAT: Age 10

```
Inputs:
    dob_days  = 16721                      // i32
    dob_iso   = "2015-10-13"               // informational
    bias      = bias_for_circuit(16721) = 0x80004151
    r_bits    = generate_commitment_randomness(
                  ChaCha20Rng::from_seed([0x08; 32]), 128)

Output:
    commitment_hex = 2b4a7ee14d0978e38c6cb90ade9d85297cfcf46823e45dc868ad5e0f09e6df0e
```

### A.9 Manifest Values for the v0.1 Production VK

```
vk_id                  = 914153247
vk_fingerprint_blake2s = 3491e619259f47b7c5b3b82ed6f71a3bf62a6c2e5a5e9349163e8c0e94c73644
vk_blake2b512_hash     = 0aed1bda4ad79cd0c166976c5ee3f2bd1f9ca983ba8af5a7c45224003a356eac6acc61209250fd08e4835994147ca2ebc8b5e3fb6abdbbaaf2cccab566bedc0a
vk_size                = 1732 bytes
pk_blake2s_hash        = 375e8913b13e234b660bf24995856c7ee59d8fc24462312714e6eebac63c745e
pk_size                = 51 844 344 bytes
circuit_constants_hash = 9dbbab7e903507b182d1d33f47c72b004e0ffb1bee2cd5ac55e7cbe060338f22
                         (v0 circuit constants)
constraints            = 99 083
public_inputs          = 8
ic_len                 = 9
kid_bytes              = 14
schema_bytes           = 12
```

These values are the gold-standard pin for v0.1 deployments.

### A.10 Credential Prehash KAT

```
Inputs:
    v       = 2
    kid     = "provii:2026-05"          (14 bytes)
    c       = 0x42 × 32                 ([0x42; 32])
    iat     = 0x0000_0000_6000_0000
    exp     = 0x0000_0000_7000_0000
    schema  = "provii.age/0"            (12 bytes)

Layout (91 bytes):
    "provii.cred.v0"                    (14 bytes)
    || 0x02                             (1 byte)
    || 0x0e                             (1 byte, len=14)
    || "provii:2026-05"                 (14 bytes)
    || 0x42 × 32                        (32 bytes)
    || 00 00 00 00 60 00 00 00          (8 bytes, BE iat)
    || 00 00 00 00 70 00 00 00          (8 bytes, BE exp)
    || 0x0c                             (1 byte, len=12)
    || "provii.age/0"                   (12 bytes)

Hex of the 91 byte prehash:
    70726f7669692e637265642e7630020e70726f7669693a323032362d30354242
    4242424242424242424242424242424242424242424242424242424242420000
    00006000000000000000700000000c70726f7669692e6167652f30

Blake2s-256 digest (32 bytes):
    617a917028201e58ee7a546d2dffa7d005a49c995ce9e23bfc77ae9550fa149c
```

### A.11 Ed25519 Attestation KAT

```
Inputs:
    signing_key bytes = 0x01, 0x02, ..., 0x20
                        (the byte sequence [0x01; 32] incrementing by 1 to 0x20)
                      = 0102030405060708090a0b0c0d0e0f10
                        1112131415161718191a1b1c1d1e1f20
    dob_days   = 7300                   (i32)
    issuer_id  = "dmv.ca.gov"           (10 bytes)
    timestamp  = 1704067200             (u64; 2024-01-01 00:00:00 UTC)
    nonce      = 0x42 × 32              ([0x42; 32])

Verifying key bytes (32 bytes; computed from the signing key per
[RFC8032] Section 5.1.5):
    79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664

Attestation message bytes (80 bytes; this is the preimage hashed with
Blake2s-256, matching `DobAttestation::compute_message_bytes` and the
construction shown below):
    "provii.attestation.dob.v0"         (25 bytes)
    || 84 1c 00 00                      (4 bytes, LE dob_days = 7300)
    || 0x0a                             (1 byte, len=10)
    || "dmv.ca.gov"                     (10 bytes)
    || 80 00 92 65 00 00 00 00          (8 bytes, LE timestamp = 1704067200)
    || 0x42 × 32                        (32 bytes)

Preimage hex (80 bytes):
    70726f7669692e6174746573746174696f6e2e646f622e7630841c00000a646d
    762e63612e676f76800092650000000042424242424242424242424242424242
    42424242424242424242424242424242

Blake2s-256 message hash (32 bytes):
    0b1aee332eb8f6cb0e4e090f001b99d077c74783d0abcb3d108e82f424757296

Ed25519 signature (64 bytes; deterministic per [RFC8032]):
    9e30ab793959301e0a308d339cd98cfbd0046ed409d68d9752a24e8906c6fd07
    3de0628ee8394d88404c11b5aa7d07024074ea86872e16bc035a1f226fca8b02
```

### A.12 Public Input Vector: End to End

From the existing committed real proof in `provii-crypto/crypto-e2e-tests/tests/test_native_verify.rs`.

```
Inputs:
    cutoff_days     = 13772
    bias(cutoff)    = bias_for_circuit(13772)
                    = (13772u32) XOR 0x8000_0000
                    = 0x800035cc
    rp_hash         = ad106802a888dcb4028cd9933d47a6c50e30d649969660f8432148c8961db6ea
    issuer_vk       = 02820bdb8c81bb4824b8b7be488765e819b84ff495d5ae334a10197fd97ddd25
    cred_nullifier  = b7e414287e1792d961939737b40d7d453cd2996e3a2c8735f745da828b8c5af3
    direction       = Over (encoded as 1)
    vk_id           = 0                  (test vector; not the production 914153247)

Committed 192 byte proof (hex):
    9819aec05f81d5e99501382392fdb60d2d46f6b58670548ee70d83a6b7bb3e4d
    5e1c9b196ae6fea81fd10875f2a2196db87dea3cfd02b4a9cde78cd6ea01b899
    30a01f52e6476ad140146ac3538ea06bb6d8c433236f110968889cb09c073502
    09d243b2be5bd96edc1642e328ed673955bff40b477ac7a3a2ec576ccd7dd9ff
    d8679286997aa0b35aa9a63b2bb21e0793c4a575a482a156fd28777296c9f429
    bd531b21db711c92da2f318f7870da8e4e0a46629cb79718c40188caddad0f38

Expected public input scalars (8 BLS12-381 field elements, canonical
32-byte little-endian repr; output of `AssemblePublicInputs` over the
inputs above):
    pi[0] = 0100000000000000000000000000000000000000000000000000000000000000
    pi[1] = cc35008000000000000000000000000000000000000000000000000000000000
    pi[2] = ad106802a888dcb4028cd9933d47a6c50e30d649969660f8432148c8961db62a
    pi[3] = 0300000000000000000000000000000000000000000000000000000000000000
    pi[4] = 02820bdb8c81bb4824b8b7be488765e819b84ff495d5ae334a10197fd97ddd25
    pi[5] = 0000000000000000000000000000000000000000000000000000000000000000
    pi[6] = b7e414287e1792d961939737b40d7d453cd2996e3a2c8735f745da828b8c5a33
    pi[7] = 0300000000000000000000000000000000000000000000000000000000000000

Note: the high bits of pi[2], pi[4], and pi[6] differ from the raw input
hashes because `multipack::compute_multipacking` packs the 256-bit input
across two BLS12-381 scalars; the upper bits are masked into the 2-bit
high-half scalars (pi[3], pi[5], pi[7]). The 254-bit field modulus
prevents direct injection of arbitrary 256-bit values.

Verification result: valid (under the matching VK from
test_native_verify; not the production VK).
```

### A.13 Notes on Test Vector Maturity (Informative)

The hex outputs in A.5 through A.12 were materialised from the reference implementation's deterministic test harness at `provii-crypto/crypto-e2e-tests/tests/spec_vectors.rs`, which is the canonical source for the values pinned in this appendix. The harness is driven by `ChaCha20Rng::from_seed([0u8; 32])` and re-runs bit-for-bit on every invocation; any drift between this appendix and the harness output is a defect in the implementation or in this document.

Implementations conforming to v0.1.0 MUST reproduce these outputs and SHOULD cross check them against the reference harness. Implementations failing to reproduce a pinned vector are non-conforming.

---

## Appendix B: Informative Examples

This appendix is informative. It contains worked examples to assist implementers in understanding the protocol flows. The examples are not normative; in case of conflict with the body of the specification, the body governs.

### B.1 Worked Issuance

A user, Alice, born 2000-10-16 (`dob_days = 11246`), enrols via an Issuing Party (the Acme Bank app) that integrates with Provii as the Issuer.

1. Alice opens the Acme Bank app, completes Acme's own KYC flow, and taps "Add my age credential".
2. The Acme Bank app (acting as the Issuing Party) authenticates to the Issuer at `POST /v0/attestation/create` using HMAC-SHA256 over its canonical request (`CLIENT_ID = "acme-bank"`, timestamp, `dob_days = 11246`, `authorizer_json` referencing the Acme session).
3. The Issuer verifies the HMAC, applies the child-DOB guard (Alice is over 18 so the request proceeds), mints a 32 byte nonce, constructs the attestation message over `(dob_days = 11246, issuer_id = "provii.issuer.v0", timestamp = now, nonce, session_id, client_id)`, signs it with its Ed25519 key, and returns the `Attestation` to the Acme Bank app. The nonce is not stored yet; it will be consumed at blind-issuance time (step 7).
4. The Acme Bank app constructs a deep link containing the base64url-encoded attestation and invokes the Provii Wallet. Alice is bounced into the Wallet.
5. The Wallet generates 128 bits of randomness from the iOS Secure Enclave CSPRNG. After validation (≥ 8 unique bytes, not all zero), the result is held in memory as `r_bits`.
6. The Wallet sends `{ "attestation": <base64url>, "r_bits": <base64url 16 bytes> }` to the Issuer at `POST /v0/issuance/blind` over TLS.
7. The Issuer verifies the attestation signature, freshness (3600 s past, 60 s future), and `dob_days` within `[-36525, +36525]`. It performs the nonce single-use check: if the nonce is already present in the consumed-nonce store, the request is rejected as a replay; otherwise the nonce is recorded with TTL `ATTESTATION_NONCE_TTL_SECONDS` (7200 seconds). It computes `c = PedersenCommit(11246, r_bits)` (32 bytes).
8. The Issuer constructs CredMsgV2 with `v = 2`, `kid = "provii:2026-05"` (exactly 14 bytes), `c`, `iat = now`, `exp = now + 7 300 days`, `schema = "provii.age/0"` (exactly 12 bytes). It computes the prehash, Blake2s hashes it, signs with RedJubjub, and self-verifies.
9. The Issuer returns the SignedCredential to the Wallet and zeroises `dob_days` and `r_bits` from memory. It writes an audit log entry containing the Acme Bank `CLIENT_ID`, timestamp, `kid`, `iat`, `exp`, and schema, with no DOB or randomness.
10. The Wallet verifies the credential: recomputes `c' = PedersenCommit(11246, r_bits)` and confirms `c' == credential.c_bytes` in constant time, verifies the RedJubjub signature, confirms `iat <= now < exp`. On success, it stores `{ SignedCredential, dob_days = 11246, r_bits }` in the iOS Keychain.

### B.2 Worked Verification (Expert Profile)

Alice attempts to access an age-restricted website. The site (Relying Party) uses the Expert integration profile.

1. The Relying Party authenticates to the Verifier with HMAC-SHA256 and requests a challenge. Its request carries `origin = "https://example.com"`, `method = "POST"`, `cutoff_days = 11246`, `expires_in = 300`, `code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"`, `verifying_key_id = 914153247`, and the `authorizer` identifying the Relying Party's registered `CLIENT_ID`.
2. The Verifier looks up the origin policy for `https://example.com`, finds `proof_direction = "over_age"`, and mints a fresh challenge: `challenge_id = "a4c8d3e0-5f1b-4a2c-9c7e-1234567890ab"` (UUIDv4), `nonce = 32 bytes from CSPRNG`, `rp_challenge = SHA-256(origin || nonce || "provii.challenge.v0")`, `submit_secret = 32 random bytes`, `short_code = "483729105648"`. It stores a `CachedChallenge` in state `Pending` with all 21 fields populated per Section 15.9.
3. The Verifier returns to the Relying Party: `{ challenge_id, rp_challenge: base64url, cutoff_days, verifying_key_id, submit_secret: base64url, expires_at, proof_direction: "over_age", short_code, status_url, verify_url }`.
4. The Relying Party renders a QR code containing the challenge fields. Alice scans it with her Wallet.
5. The Wallet performs preflight (Section 13.5): recomputes `c'` from her stored `dob_days = 11246` and `r_bits`, confirms `c' == credential.c_bytes`, verifies the RedJubjub signature off-circuit, confirms the credential has not expired, locally checks `bias(11246) >= bias(11246)` (boundary case passes).
6. The Wallet computes `cred_nullifier = PedersenNullifier(credential.c_bytes)` and `rp_hash = Blake2s-256(rp_challenge)`.
7. The Wallet generates a Groth16 proof. After approximately 5 seconds of CPU on her phone, the proof is ready.
8. The Wallet posts a `SubmitProofRequest` to `POST /v0/verify`:
   ```json
   {
     "challenge_id":  "a4c8d3e0-5f1b-4a2c-9c7e-1234567890ab",
     "submit_secret": "BASE64URL32...",
     "proof": {
       "verifying_key_id": 914153247,
       "public": {
         "cutoff_days":    11246,
         "rp_challenge":   "BASE64URL32...",
         "issuer":         { "value": "BASE64URL32..." },
         "cred_nullifier": "BASE64URL32..."
       },
       "proof": "BASE64URL_OF_192_BYTES..."
     }
   }
   ```
9. The Verifier runs Section 14.6 step 10: loads the CachedChallenge, validates `submit_secret` and `rp_challenge` in constant time (`subtle::ConstantTimeEq::ct_eq`), recomputes `rp_hash`, checks the ban store (no entry, no insertion since the nullifier was not banned), looks up the issuer in its allowlist (Active), looks up `verifying_key_id = 914153247` in `VK_REGISTRY`, assembles the public inputs using `proof_direction = "over_age"` from the stored record, and runs `bellman::groth16::verify_proof`. The result is true.
10. The Verifier transitions `CachedChallenge.state` from `Pending` to `ProofOkWaitingForRedeem` and records `result = Some(true)`.
11. The Relying Party redeems the result at `POST /v0/challenge/a4c8d3e0-5f1b-4a2c-9c7e-1234567890ab/redeem` with body `{ "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" }`. The Verifier compares `SHA-256(code_verifier)` against the decoded `code_challenge` bytes in constant time, transitions the state to `Verified`, and returns `{ "result": "OK", "verified": true }`.
12. The Relying Party grants Alice access.

The total time from QR scan to access grant is approximately 6 to 8 seconds, dominated by the 5 second proof generation on the Wallet.

### B.3 Worked Failure: Replay Attempt

A malicious actor captures Alice's proof submission from step 8 of B.2 and attempts to reuse it.

1. The attacker captures the full `SubmitProofRequest` body in transit. It now holds the nested `{ challenge_id, submit_secret, proof: { verifying_key_id, public, proof } }` object.
2. The attacker attempts to replay the submission verbatim to the same Verifier. The Verifier looks up the `CachedChallenge` and finds state `Verified`; the submission is rejected with `ApiError::BadRequest` and code `CHALLENGE_ALREADY_CONSUMED`.
3. The attacker constructs a new challenge request to the Verifier (the attacker is itself a registered Relying Party with `CLIENT_ID` = "attacker"). The new challenge carries a different `rp_challenge` and different `submit_secret`. The attacker then submits Alice's captured proof under the new `challenge_id`. The proof verification fails: the public input `rp_challenge` in the captured proof does not equal the Verifier's stored `rp_challenge` for the new challenge, so the constant-time comparison in step 10c fails and the Verifier returns `INVALID_CHALLENGE`.
4. The attacker attempts to forge a correct `submit_secret` for the new challenge. The `submit_secret` is 32 bytes of CSPRNG and is not disclosed to any party other than the original Relying Party; the attacker has no way to learn it. The Verifier rejects at step 10b with `INVALID_SUBMIT_SECRET`.

The proof cannot be replayed.

### B.4 Worked Failure: Expired Credential

Alice's credential expired yesterday (`exp < now`). She attempts to verify.

1. Steps 1 through 4 proceed as in B.2.
2. At preflight (step 5), the Wallet checks `credential.exp > current_time`. The check fails. The Wallet displays "your credential has expired; please re-enrol" and does NOT generate a proof.
3. If a malicious or buggy Wallet skips preflight, it may submit a proof from an expired credential. The proof verifies cryptographically because the circuit does not bind `exp` to the current time, and the Verifier does not receive `iat` or `exp`. The Verifier CANNOT reject the proof on expiry grounds in v0.1.

Confirmed against the reference `provii-verifier/src/routes/verify.rs`: the Verifier calls `provii_crypto_verifier::verify_age_snark(proof_bytes, proof_direction, cutoff_days, rp_hash, issuer_vk_bytes, cred_nullifier, verifying_key_id)` and never sees `iat` or `exp`. The credential body is held only by the Wallet. Expiry enforcement is therefore entirely wallet-side. Relying Parties that require a server-side expiry guarantee MAY require the Issuer to issue shorter-lived credentials as one mitigation; this is an explicit departure from the default posture that credentials age with the user (see Section 17.11 and Section 17.12).

---

## Appendix C: Data Structures

This appendix is informative. It defines language specific data structure shapes for Rust implementations. Other languages SHOULD use equivalent shapes that round trip the same wire bytes.

### C.1 CredMsgV2

```rust
struct CredMsgV2 {
    v:        u8,
    kid:      String,       // exactly 14 bytes UTF-8 for circuit compatibility
    c_bytes:  [u8; 32],
    iat:      u64,
    exp:      u64,
    schema:   String,       // exactly 12 bytes UTF-8 for circuit compatibility
}
```

The reference Rust type uses `String` for `kid` and `schema`; the circuit requires exactly 14 bytes and 12 bytes respectively (see Section 12.4). The Issuer MUST enforce the length constraints before signing.

### C.2 SignedCredential

```rust
struct SignedCredential {
    v:           u8,
    kid:         String,
    c_bytes:     [u8; 32],
    iat:         u64,
    exp:         u64,
    schema:      String,
    issuer_vk:   [u8; 32],
    sig_rj:      [u8; 64],
}
```

The `sig_rj` field holds the 64 byte RedJubjub signature over the credential prehash, laid out as `R_bytes(32) || s_bytes(32)`.

### C.3 AgeSnarkProofV2 (Canonical Form)

```rust
struct AgeSnarkProofV2 {
    v:        u8,
    vk:       u32,           // verifying key identifier
    rp_hash:  [u8; 32],      // Blake2s wrap of rp_challenge
    cutoff:   i32,
    proof:    Vec<u8>,       // Bellman Groth16 proof; 192 bytes for v0.1 circuit
}
```

The `vk` field is `u32`. Implementations MUST use `u32`; `u16` is insufficient for the production `vk_id = 914153247` (which exceeds `u16::MAX = 65535`). Both `provii-crypto/crypto-prover/src/lib.rs` (`AgeSnarkProofV2Extended.vk`) and `provii-crypto/crypto-commons/src/lib.rs` (`AgeSnarkProofV2.vk`) declare this field as `u32`.

### C.4 AgeSnarkProofV2Extended

```rust
struct AgeSnarkProofV2Extended {
    v:                  u8,
    vk:                 u32,
    rp:                 [u8; 32],       // rp_hash (Blake2s wrap of rp_challenge)
    cutoff:             i32,
    issuer_vk_bytes:    [u8; 32],
    cred_nullifier:     [u8; 32],
    direction:          ProofDirection,
    proof:              Vec<u8>,
}
```

This is the form used by the prover library to hold all data required for downstream submission. The `proof` field is exactly 192 bytes. The field is named `rp` in the Rust source; `rp_hash` is the semantic name used in this specification.

### C.5 DobAttestation

```rust
struct DobAttestation {
    dob_days:    i32,
    issuer_id:   String,
    timestamp:   u64,
    nonce:       [u8; 32],
    session_id:  String,
    client_id:   String,
    signature:   [u8; 64],
}
```

The wire JSON encodes `nonce` and `signature` as lower-case hex (see Section 15.4). `session_id` and `client_id` are covered by the Ed25519 signature; see Section 10.2 for the canonical bytes.

### C.6 AgePublic

```rust
struct AgePublic {
    direction:        ProofDirection,
    cutoff_days:      i32,
    rp_hash:          [u8; 32],
    issuer_vk_bytes:  [u8; 32],
    cred_nullifier:   [u8; 32],
}
```

### C.7 AgeWitness

```rust
struct AgeWitness {
    dob_days:         i32,
    r_bits:           Vec<bool>,         // exactly 128
    issuer_vk_bytes:  [u8; 32],
    sig_rj_bytes:     Vec<u8>,           // exactly 64
    v:                u8,
    kid:              Vec<u8>,           // exactly 14
    c_bytes:          [u8; 32],
    iat:              u64,
    exp:              u64,
    schema:           Vec<u8>,           // exactly 12
}
```

`AgeWitness` MUST be `Clone + Zeroize + ZeroizeOnDrop`. `Serialize` and `Deserialize` MUST NOT be implemented.

### C.8 ProofDirection

```rust
enum ProofDirection {
    OverAge,   // cutoff >= dob (user is at least min_age)
    UnderAge,  // dob >= cutoff (user is at most max_age)
}
```

The wire JSON representation uses snake_case strings: `"over_age"` and `"under_age"`. The circuit public-input bit encoding is `1` for `OverAge` and `0` for `UnderAge`.

### C.9 CachedChallenge (Verifier Internal)

```rust
struct CachedChallenge {
    id:                  String,
    rp_challenge:        [u8; 32],
    cutoff_days:         i32,
    verifying_key_id:    u32,
    code_challenge:      String,
    submit_secret:       [u8; 32],
    origin:              String,
    expires_at:          u64,
    proof_direction:     ProofDirection,
    state:               ChallengeState,
    short_code:          String,
    status_url:          String,
    verify_url:          String,
    created_at:          u64,
    client_id:           String,
    result:              Option<bool>,
    failure_code:        Option<String>,
    redeemed_at:         Option<u64>,
    proof_submitted_at:  Option<u64>,
    ip_hash:             Option<String>,
    user_agent_hash:     Option<String>,
}

enum ChallengeState {
    Pending,
    ProofOkWaitingForRedeem,
    Verified,
    Failed,
    Expired,
}
```

See Section 15.9 for field descriptions.

### C.10 SubmitProofRequest (Wallet to Verifier)

```rust
struct SubmitProofRequest {
    challenge_id:    String,
    submit_secret:   [u8; 32],
    proof:           AgeProofJson,
}

struct AgeProofJson {
    verifying_key_id: u32,
    public:           PublicInputsJson,   // Section 15.6
    proof:            [u8; 192],
}
```

The proof submission is a nested JSON object. See Section 15.10 for the full wire example.

---

## Appendix D: Dependency Versions

This appendix is informative.

The reference implementation tracks the following crate versions for v0.1 deployments. Other implementations need not use these exact crates but MUST produce equivalent wire bytes.

| Crate | Version | Purpose |
|---|---|---|
| `bellman` | 0.14 | Groth16 proving system |
| `bls12_381` | 0.8 | BLS12-381 pairing curve |
| `jubjub` | 0.10 | Jubjub curve |
| `ed25519-dalek` | 2.1 | Ed25519 signatures |
| `blake2` | 0.10 | Blake2s-256 (Digest trait, no personalisation) |
| `blake2s_simd` | 1.0 | Blake2s-256 with personalisation |
| `sha2` | 0.10 | SHA-256 |
| `sapling-crypto` | 0.5 | Pedersen hash (`NoteCommitment` personalisation, fixed generator tables), Jubjub arithmetic gadgets reused by the age circuit |
| `ff` | 0.13 | Field arithmetic traits |
| `group` | 0.13 | Group arithmetic traits |
| `zeroize` | 1.8 | Secret key zeroing |
| `subtle` | 2.6 | Constant time operations |

Minimum supported Rust version: **1.83**.

### Post Quantum Outlook

The current cryptographic primitives are not post quantum secure. A sufficiently capable quantum adversary breaks discrete log on Jubjub and BLS12-381, defeating both the credential signature and the Groth16 proof.

The Provii protocol is designed for algorithm agility: the credential `v` byte, the circuit constants version (`v0`), and the `vk_id` enable transitions to new primitives without disturbing existing wire formats at the JSON envelope level. A future v1.0 of this specification may introduce post quantum alternatives such as a SNARK constructed from lattice-based commitments and hash based signatures.

The migration trajectory is informative; v0.1 is a classical-only specification.

---

## Appendix E: Deviations from Zcash

This appendix is informative; normative behaviour is fixed by Sections 4, 7, 8, 9, and 12.

Provii shares cryptographic primitives with Zcash Sapling (curves, generator point, Pedersen hash, Groth16, BLS12-381). It is not Zcash compatible at the protocol level. Zcash transactions, proofs, signatures, and commitments cannot be substituted for Provii equivalents.

### E.1 RedJubjub Modifications

| Aspect | Zcash RedJubjub | Provii RedJubjub |
|---|---|---|
| Challenge hash | BLAKE2b-512 with Zcash-specific DST | Blake2s-256 with `"ProviiRJ"` personalisation, wide reduced to `Fr_J` |
| Nonce derivation | Per Zcash spec (random or derived) | `Blake2s-256("ProviiRJ/nonce" \|\| sk \|\| msg_hash)`, wide reduced |
| Message format | Zcash transaction sighash | Credential prehash (Section 8.2) |
| Generator | Zcash spending key generator | Same byte sequence, loaded directly via `SubgroupPoint::from_bytes` |
| RP binding | Not applicable | RP hash carried in a public input; v0.1 does NOT consume RP-bound signatures |
| Signing key deserialisation | Accepts any 32 byte canonical scalar including zero | `SigningKey::from_bytes` rejects zero scalars explicitly |
| Verifying key deserialisation | Accepts subgroup identity in some paths | `VerificationKey::from_bytes` rejects subgroup identity and small-subgroup elements |
| Batch verification | Ships `batch.rs` for aggregated verification | Not implemented; Provii verifies signatures one at a time. The upstream batch API is not exposed. |

### E.2 Pedersen Hash Usage

| Aspect | Zcash Sapling | Provii |
|---|---|---|
| Personalisation | `NoteCommitment` for note commitments | `NoteCommitment` for DOB commitments (same personalisation, different input) |
| Input format | Note fields per Zcash spec | `bits_le(bias_for_circuit(dob_days), 32) \|\| r_bits` |
| Nullifier | Derived from note commitment plus a nullifier key | `H_ped(MerkleTree(0), bits_le(NULLIFIER_DST) \|\| bits_le(c))` |
| Nullifier DST | Not applicable (Zcash uses a per-user nullifier key) | `"provii.nullifier.pedersen.v0"` as bit input |

### E.3 Circuit Differences

| Aspect | Zcash Sapling | Provii |
|---|---|---|
| Purpose | Shielded transactions | Age threshold verification |
| Public inputs | Value commitment, nullifier, others | 8 elements: direction, cutoff, rp_hash, issuer_vk, nullifier |
| Constraints | Approximately 100 000 (Sapling Spend) | 99 083 |
| In circuit signatures | None | RedJubjub verification in circuit |
| Predicate | Note value balance | Direction-dependent age comparison via conditional swap |
| Fixed field sizes | Not applicable | kid = 14 bytes, schema = 12 bytes, r_bits = 128 bits |
| Proving system | Groth16 over BLS12-381 | Same |

### E.4 No Zcash Compatibility

This implementation shares primitives with Zcash. It is not compatible at the protocol level. Zcash spending keys, viewing keys, addresses, transactions, proofs, and commitments cannot be used interchangeably with Provii equivalents.

---

## Appendix F: Deferred to Future Versions

This appendix is informative. It documents protocol features present in earlier drafts of this document that have been deferred pending further design work. An implementation claiming "Provii v0.1 Compliant" MUST NOT emit or consume any of the constructions in this appendix as part of the v0.1 wire protocol.

### F.1 Issuance Consent Message

Earlier drafts specified a SHA-256-based consent message that a Wallet would sign during issuance to bind the Wallet's public key, issuer, `kid`, terms version, and a nonce. The construction as drafted had no pinned wallet signature scheme, no defined `wallet_pubkey` type, and no consumer in the normative flow. It is removed from v0.1.

A future version may revive this mechanism to provide a cryptographic record of wallet consent at issuance. The revival will specify the signature scheme, the wallet key provenance and registry, the signature verification flow at the Issuer, and a length-prefixed preimage aligned with the rest of v0.x.

### F.2 Site-Key-Bound Challenge Signing

Earlier drafts specified a SHA-256 construction named `hash_challenge_v1` which the Verifier would sign with a "site key" so that Wallets could verify challenge provenance before committing CPU to proof generation. The construction had no pinned signature scheme, and the Wallet-side verification flow was optional.

It is removed from v0.1. A future version may revive this binding with a pinned signature scheme, pinned key distribution mechanism, and normative verification flow at the Wallet.

### F.3 AgeChallenge Transport Structure

The `AgeChallenge` structure (with `site_key_id` and `site_signature` fields) was the wire carrier for Section F.2. It is removed from v0.1 alongside the signing construction. The v0.1 challenge transport uses the JSON payload returned by Section 14.2 step 4 directly.

### F.4 Reserved DSTs

The identifiers `PROOF_V2_DST`, `COMMITMENT_HASH_DOMAIN`, `CREDENTIAL_DOMAIN`, and `SCHNORR_BLIND_DOMAIN` appeared in earlier drafts under a "Reserved DSTs" table. They are not reserved in v0.1, and the corresponding `pub const` declarations have been removed from `provii-crypto/crypto-commons/src/constants.rs`. A future version that introduces new constructions will pick DSTs at that time; pre-reservation is unnecessary.

---

## Appendix G: Acknowledgements

The Provii protocol owes its cryptographic foundations to the work of many researchers and engineers.

The Zcash Sapling design (Sean Bowe, Daira Hopwood, Nathan Wilcox, Jack Grigg, and the broader Zcash team) provides the BLS12-381 / Jubjub stack, the Pedersen commitment, the original RedJubjub signature scheme, and the trusted setup machinery on which Provii builds. The `bellman` and `sapling-crypto` Rust crates are direct dependencies.

The Groth16 proving system is due to Jens Groth (Eurocrypt 2016).

The deterministic nonce derivation pattern ([RFC6979]) due to Thomas Pornin influenced Provii's RedJubjub nonce construction, although Provii substitutes Blake2s for HMAC-SHA-256 for in-circuit efficiency.

The `arkworks` project and the Zcash Foundation provided cross-implementation reference points during specification authoring.

Maelstrom AI conducted the protocol design, implementation, and security review across the provii-verifier, provii-issuer, provii-crypto, and provii-mobile-sdk codebases.

---

## Authors' Addresses

Tim O'Connor (editor)
Maelstrom AI Pty Ltd ATF Maelstrom AI Holding Trust
PO Box 169
St Arnaud VIC 3478
Australia
Email: spec@provii.app

Maelstrom AI Pty Ltd
ATF Maelstrom AI Holding Trust
ABN: 61 633 823 792
PO Box 169
St Arnaud VIC 3478
Australia

Email: spec@provii.app
Security contact: security@provii.app
Errata: `https://github.com/provii/provii-protocol-spec/issues`
