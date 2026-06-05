# Contributing

The Provii protocol specification is the canonical normative description of the protocol. Changes come in by pull request, and the bar is high: a substantive change usually needs a matching update to the reference implementation in `provii-crypto` and a re-run of the test vectors.

## What changes are accepted

### Editorial changes

Typos, broken links, citation fixes, and wording that does not change conformance come in as a straightforward PR. Add a one-line rationale for anything beyond a typo.

### Substantive changes

New requirements, changed byte layouts, or new conformance rules need an issue first. They usually require a matching change in `provii-crypto` and a re-run of the test vectors.

## Versioning

The repository tags releases from v0.1.0 under [0ver](https://0ver.org/). The protocol edition is frozen at its version-numbered path, currently `v0/`. A breaking change to the wire format lands in a new edition directory; an existing edition does not mutate. Editorial fixes that do not change conformance ship as patch releases such as v0.1.1.

## Test vectors

Every pinned hex value in Appendix A must be reproducible from the reference test in `provii-crypto/crypto-e2e-tests/tests/spec_vectors.rs`. If your change affects any pinned value, update both the spec text and the test, then confirm the test is deterministic across two consecutive runs.

## Patent grant

By contributing you agree that your contribution is licensed under the same terms as the rest of the document (CC BY 4.0) and that you make no patent claims against compliant implementations.
