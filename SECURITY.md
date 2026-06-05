# Security Policy

## Reporting a vulnerability

Report a suspected vulnerability in the Provii protocol specification or its reference artefacts to **security@provii.app**. Do not open a public issue for a security-affecting finding before it has been triaged.

Where you can, include the section number and the exact text or byte value in question, with a reproduction or a pointer to the relevant source artefact, plus your assessment of impact.

We acknowledge a report within five business days and keep you updated as we investigate.

## Scope

This repository is a specification, not a deployed service. Findings of interest are errors in the normative cryptographic constructions or wire formats that would weaken a compliant implementation, and test vectors that fail to reproduce or that disagree with the reference implementation in [provii-crypto](https://github.com/provii/provii-crypto). An ambiguity that could lead two independent implementations to interoperate incorrectly in a way that affects security is also in scope.

Vulnerabilities in a deployed Provii service belong in that service's own repository. The protocol contact for the specification itself is spec@provii.app.

## Disclosure

We follow coordinated disclosure. Once a fix or erratum is agreed, we credit reporters who want it.
