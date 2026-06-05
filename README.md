# Provii Protocol Specification

This repository hosts the canonical specification for the **Provii privacy-preserving age verification protocol**.

- **Canonical URL**: <https://spec.provii.app/v0/protocol.html>
- **Latest stable**: [v0.1.0](v0/protocol.md)
- **Reference test vectors**: [v0/protocol.md Appendix A](v0/protocol.md), reproducible via [`provii-crypto/crypto-e2e-tests/tests/spec_vectors.rs`](https://github.com/provii/provii-crypto/blob/main/crypto-e2e-tests/tests/spec_vectors.rs)
- **Reference implementation**: [provii/provii-crypto](https://github.com/provii/provii-crypto)

## What this is

A specification of the cryptographic primitives, wire formats, protocol flows, and conformance rules that any implementation must follow to be interoperable with the Provii network. Written for engineers building wallets, issuers, verifiers, or independent re-implementations.

This is not a marketing document or a product overview. Those live at <https://provii.app>.

## Versioning

The repository follows [0ver](https://0ver.org/): releases tag from `v0.1.0` and the major version stays at zero. The protocol is versioned on its own axis. Frozen protocol editions live under `v{N}/`; the current edition is `v0`. A breaking change to the wire format lands as a new `v{N}/` directory rather than mutating an existing one.

## Patent

Australian Provisional Patent Application No. 2026901546, filed 26 February 2026. A royalty-free patent grant covers compliant implementations, with defensive termination. Full statement in [v0/protocol.md §Copyright and Licence Notice](v0/protocol.md).

## Document licence

This specification is published under [CC BY 4.0](LICENSE).

## Reporting issues

Errata and questions go to <https://github.com/provii/provii-protocol-spec/issues>. A security-affecting erratum goes to security@provii.app first, before any public disclosure.

## Conformance

An implementation may claim "Provii v0 Compliant" if it satisfies every MUST in [v0/protocol.md §Conformance](v0/protocol.md). The reference test vectors in Appendix A are normative: an implementation MUST reproduce every pinned hex value bit for bit.
