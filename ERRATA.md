# Errata

## BONP-1.0-E1 — canonical serialization erases nested objects

**Severity: critical. Affects every BONP-1.0 envelope and signature.**

### What the spec said

SPEC §3.1 described canonical serialization correctly in prose:

> Serializing the claim object to JSON with **lexicographically sorted keys at every nesting level**.

and then gave a normative code sample that does not do that:

```typescript
function canonicalizeClaim(claim: BiometricClaim): string {
  return JSON.stringify(claim, Object.keys(claim).sort());
}
```

### What it actually does

The second argument to `JSON.stringify` is a _replacer_. When it is an array, it is a key allow-list — and it applies at **every nesting depth**, not just the top level. `Object.keys(claim)` returns only the top-level keys, so every nested object is filtered down to nothing.

A full envelope serializes to this, regardless of its contents:

```
{"attestation":{},"claim":{},"settlement":{},"version":"BONP-1.0"}
```

The metric, the value, the subject, the timestamps, the nonce, the public key — all of it disappears.

### Consequences

1. **`envelope_id` is a constant.** SPEC §4.2 defines `DisputeRecord.envelope_id` as "SHA-256 of canonical envelope JSON". Under 1.0 every envelope hashes to `5e31b607a2641486…`. Envelope IDs cannot identify envelopes, so a dispute cannot name the envelope it disputes.

2. **One signature validates every claim.** SPEC §3.2 signs `canonicalizeClaim(envelope.claim)`. Since that message is identical for all claims with the same top-level shape, a signature harvested from any envelope verifies against any other. An attacker who has seen one legitimately signed recovery score can attach that signature to a fabricated claim of any value, for any subject, and it verifies.

That second point is a total break of the protocol's trust model. BONP-1.0 must not be used to settle anything.

### The fix, in BONP-1.1

`canonicalize()` and `canonicalizeClaim()` now implement [RFC 8785 (JSON Canonicalization Scheme)](https://www.rfc-editor.org/rfc/rfc8785): keys sorted by UTF-16 code unit at every level, no whitespace, UTF-8 output, and an explicit rejection of values JSON cannot represent deterministically (`NaN`, `Infinity`, `BigInt`, `Date`, functions, cyclic references).

`verifyEnvelope()` additionally performs real Ed25519 verification. BONP-1.0 checked only that `provider_signature` was a non-empty string, so `"x"` passed.

Both defects are pinned by regression tests in `test/canonical.test.ts`, which keep a copy of the 1.0 canonicalizer and assert that it produced the collision. If those tests ever fail, this document is wrong.

### Migration

Envelope IDs and signatures produced under 1.0 do not carry over. There is no compatibility shim, deliberately: a shim would mean accepting 1.0 signatures, which is the vulnerability.

- Re-sign any envelope you intend to keep.
- Discard stored `envelope_id` values; recompute them.
- Reject `version: "BONP-1.0"` at the verifier.

### Credit

Found while auditing the SDK against its own specification. The prose in §3.1 was right the whole time; only the code sample was wrong, which is why it survived review — the sentence above it describes the correct behaviour, and the reader's eye supplies it.
