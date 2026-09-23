# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[Private Security Advisory](https://github.com/Secure-Vector/securevector-sdk-js/security/advisories/new)
or by emailing **security@securevector.io**. Do **not** file public issues for
security vulnerabilities.

We aim to acknowledge reports within 2 business days and to give a fix or
mitigation timeline within 14 days for high-severity issues.

## Supported versions

Security fixes land on the latest `6.x` release.

## Verifying what you installed

Every release from 6.0.1 on is published by this repository's
[Release workflow](.github/workflows/release.yml) through npm trusted publishing,
after a manual approval, and carries a signed provenance attestation that links
the package to the exact commit and workflow run that built it.

```bash
npm install @securevector/sdk
npm audit signatures
```

`npm audit signatures` should report verified registry signatures and verified
attestations for `@securevector/sdk` (and for `securevector`, if you use the
alias). The npm package page shows the same provenance under **Provenance**.

6.0.0 was a one-time bootstrap publish and has no attestation; prefer 6.0.1 or
later.

## Scope

The SDK has zero runtime dependencies. It sends data only to the SecureVector
app or the endpoint you set in `SECUREVECTOR_ENGINE_ENDPOINT`, masks credential
shapes before anything leaves the process, and fails open. A way to make it send
data elsewhere, skip masking, or throw into the host agent is in scope.
