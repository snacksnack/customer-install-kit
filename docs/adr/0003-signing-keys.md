# ADR 0003: Ownership and trust of release signing and report keys

Status: proposed (pending Reid's accept) · 2026-11-10 · RC1-638

## Decision

Two key families, two owners, and a deliberately limited claim for each.

### Release signing (vendor-owned)

- ESP release artifacts (the image reference and install-kit release files) are signed in CI with **Sigstore keyless signing (cosign)**: the signing identity is the GitHub Actions OIDC identity of the vendor repo's release workflow, witnessed in the public Rekor transparency log. No long-lived private key exists to store, leak, or rotate.
- **Claim:** provenance and integrity — "this artifact was produced by this repo's release workflow at this commit, and has not been modified." The customer's installer verifies the signature before deploying (Phase 2).
- Trust root: Sigstore's public good instance + the pinned repo/workflow identity, both stated in the install docs.

### Customer report keys (customer-owned)

- At install, the kit generates a **per-install report keypair** in the customer environment. The private key never leaves it; the public key is registered in the install record the customer shares with the vendor. Conformance and diagnostic bundles are signed with it (Phase 3/4).
- **Claim:** integrity and origin binding — "this report is unmodified since signing and was produced by the install that holds this key." 
- **Explicit non-claim (from RC1-638):** this is NOT attestation. The customer controls the environment and the key, and could fabricate a report and sign it. No TPM/TEE story is implied, and the engagement writeup must say so. The signature protects against tampering in transit and cross-install mix-ups, nothing stronger.

## Why not vendor-issued report keys

A vendor-issued key would have to travel into the customer environment, inverting the whole boundary (ADR 0002): the vendor would hold material that authenticates customer output, and leaking it would let anyone forge "customer" reports. Customer-generated keys keep every credential on the side that owns it.

## Consequences

- Phase 2 adds signature verification to the install path and docs; an unsigned or mismatched artifact is an install-time hard failure (that one belongs in the preflight coverage suite, not the headline).
- Phase 3/4 report formats carry the signature and the public-key fingerprint.
- Key loss customer-side = generate a new pair and re-register; old reports stay verifiable against the old public key.
