# BONP — Biometric Oracle Network Protocol

A signed-envelope format for biometric claims, so that a prediction market settling on someone's recovery score can verify where that number came from instead of trusting whoever submitted it.

Three things recur every time a market tries to settle on body data: every implementation rewrites the device adapters, raw API responses carry no attestation, and nothing stops an attacker replaying a favourable measurement from last Tuesday. BONP is a data protocol — a typed adapter interface, a signed envelope, a dispute pathway. No chain required.

[SPEC.md](SPEC.md) is the normative document. This README is the orientation.

## Start here: version 1.0 is broken

I audited this SDK against its own specification and found that **BONP-1.0 signatures are universally forgeable**.

The spec prescribed this canonicalization:

```typescript
JSON.stringify(claim, Object.keys(claim).sort());
```

`JSON.stringify`'s second argument is a replacer, not a sorter. As an array it is a key allow-list applied at _every_ nesting depth, so a top-level key list erases every nested object. Every envelope in the protocol serialized to the same 66 bytes:

```
{"attestation":{},"claim":{},"settlement":{},"version":"BONP-1.0"}
```

Which means `envelope_id` was a constant — the same SHA-256 for every envelope ever produced. And because §3.2 signs over that string, a signature harvested from any valid envelope verifies against a fabricated claim of any value, for any subject. Sign one honest recovery score, and you can settle any market.

The prose in §3.1 said "sorted keys at every nesting level," which is correct. Only the code sample below it was wrong, and the sentence above it is exactly what stops a reader noticing.

[ERRATA.md](ERRATA.md) has the full write-up. Version 1.1 replaces canonicalization with [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) and adds real Ed25519 verification — 1.0 checked only that the signature field was a non-empty string, so `"x"` passed.

The 1.0 canonicalizer is kept in the test suite so the defect stays pinned:

```typescript
it("gave two unrelated claims the same envelope id", () => {
  const mine = bonp10Canonicalize(
    envelope({ metric: "recovery_score", value: 17, subjectId: "param" }),
  );
  const theirs = bonp10Canonicalize(
    envelope({ metric: "strain", value: 99, subjectId: "someone-else" }),
  );
  expect(id(mine)).toBe(id(theirs));
});
```

If that test ever fails, the history in ERRATA.md is wrong and should be corrected.

## The envelope

```typescript
{
  version: "BONP-1.1",
  claim: {
    metric: "recovery_score",           // canonical identifier, not the vendor's field name
    value: 17,
    timestamp: "2026-04-19T06:00:00Z",  // when the body produced it
    window: { start, end },             // what period it summarises
    device: { provider: "whoop", model: "4.0" },
    subject: { id, data_hash },         // hashed, never the raw account id
  },
  attestation: {
    adapter_id, nonce,                  // 32 random bytes, one per envelope
    fetch_timestamp,                    // when the adapter read it
    provider_public_key, provider_signature,
  },
  settlement: { staleness_window_ms, confidence_score, dispute_window_ms },
}
```

The separation that matters is `timestamp` versus `fetch_timestamp`. One is when the measurement happened, the other is when the oracle saw it, and the gap between them is the staleness check. A replayed measurement fails not because it is wrong but because it is old.

The signature covers the claim alone, not the whole envelope, so settlement metadata can be amended in a dispute without invalidating the subject's signature.

## Usage

```bash
pnpm install
pnpm test        # 29 tests
pnpm build
```

```typescript
import {
  createEnvelope,
  verifyEnvelope,
  signClaim,
  publicKeyFor,
} from "@bonp/sdk";

const signature = signClaim(claim, adapterPrivateKey);
const envelope = createEnvelope(
  claim,
  { ...attestation, provider_signature: signature },
  settlement,
);

const { valid, errors } = await verifyEnvelope(envelope);
```

Verification checks structure, replay (nonce registry), staleness, a confidence floor, and the Ed25519 signature over the canonical claim.

Reference adapters for Whoop, Oura, and Apple Health are in `src/adapters/`.

## What this does not do

Stating the limits plainly, because a protocol that overstates its guarantees is worse than one that has none.

**The public key travels inside the envelope.** So signature verification proves the claim was not altered after signing. It does not prove the signer is who they claim to be — an attacker can generate a keypair, sign a fabricated claim, and ship both. Binding `adapter_id` to a known key is the verifier's job and BONP does not do it for you. A real deployment needs a key registry.

**v1 signatures are adapter signatures, not device signatures.** The adapter attests that it fetched this value. Whoop did not sign anything. This moves the trust boundary from "whoever submitted the number" to "whoever runs the adapter", which is an improvement and not a solution. Provider-native signing is the v2 question, and it depends on device manufacturers exposing signing infrastructure that currently does not exist.

**The nonce registry is in-process.** Fine for one verifier, useless across a fleet. Production wants Redis with a TTL of `dispute_window_ms`.

**`confidence_score` is not calibrated.** It is a number an adapter asserts. Nothing checks it against outcomes.

## Status

Specification and reference SDK. It has never settled a real market.

## License

MIT.
