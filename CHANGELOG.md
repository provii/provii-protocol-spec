# Changelog

All notable changes to the Provii protocol specification.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases follow [0ver](https://0ver.org/): the major version stays at zero.

## [v0.1.0] (unreleased)

First Provii release of the protocol specification.

- Three-party protocol (Issuer, Wallet, Verifier) with bidirectional age threshold proofs.
- Cryptographic primitives: Groth16 over BLS12-381, Pedersen commitments on Jubjub, RedJubjub credential signatures, Ed25519 issuer attestations, Blake2s-256 and SHA-256 hashing.
- 192-byte zero knowledge proofs that reveal only a binary age bracket.
- A single circuit handles both Over and Under directions via a public direction bit.
- Full wire format specification with pinned byte layouts.
- Conformance section and normative test vectors in Appendix A, reproducible via the reference implementation in provii-crypto.
