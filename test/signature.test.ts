import { describe, expect, it } from "vitest";

import {
  generatePrivateKey,
  publicKeyFor,
  signClaim,
  signingMessage,
  verifyClaim,
} from "../src/signature.js";
import type { BiometricClaim } from "../src/types.js";

function claim(value = 17): BiometricClaim {
  return {
    metric: "recovery_score" as never,
    value,
    timestamp: "2026-04-19T06:00:00Z",
    window: { start: "2026-04-18T06:00:00Z", end: "2026-04-19T06:00:00Z" },
    device: { provider: "whoop" as never, model: "4.0" },
    subject: { id: "subject-a", data_hash: "abc123" },
  } as BiometricClaim;
}

const KEY = generatePrivateKey();
const PUB = publicKeyFor(KEY);

describe("claim signatures", () => {
  it("verifies a signature it produced", () => {
    expect(verifyClaim(claim(), signClaim(claim(), KEY), PUB)).toBe(true);
  });

  it("rejects a signature once the value is altered", () => {
    // This is the attack the canonicalization defect made possible: change
    // the recovery score, keep the signature, settle the market.
    const sig = signClaim(claim(17), KEY);
    expect(verifyClaim(claim(99), sig, PUB)).toBe(false);
  });

  it("rejects a signature from a different key", () => {
    const other = generatePrivateKey();
    expect(verifyClaim(claim(), signClaim(claim(), other), PUB)).toBe(false);
  });

  it("is insensitive to key order in the claim object", () => {
    const sig = signClaim(claim(), KEY);
    const reordered = JSON.parse(
      JSON.stringify({
        subject: claim().subject,
        value: claim().value,
        metric: claim().metric,
        device: claim().device,
        window: claim().window,
        timestamp: claim().timestamp,
      }),
    ) as BiometricClaim;
    expect(verifyClaim(reordered, sig, PUB)).toBe(true);
  });

  it("signs the canonical bytes, not the object identity", () => {
    const a = signingMessage(claim());
    const b = signingMessage(
      JSON.parse(JSON.stringify(claim())) as BiometricClaim,
    );
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("returns false rather than throwing on malformed material", () => {
    // The public key arrives inside the envelope under verification, so a
    // verifier that throws on bad input is a denial-of-service surface.
    expect(verifyClaim(claim(), "not-hex", PUB)).toBe(false);
    expect(verifyClaim(claim(), "ab", PUB)).toBe(false);
    expect(verifyClaim(claim(), signClaim(claim(), KEY), "zz")).toBe(false);
    expect(verifyClaim(claim(), "", "")).toBe(false);
  });

  it("rejects an all-zero signature", () => {
    expect(verifyClaim(claim(), "0".repeat(128), PUB)).toBe(false);
  });

  it("produces 64-byte signatures and 32-byte public keys", () => {
    expect(signClaim(claim(), KEY)).toMatch(/^[0-9a-f]{128}$/);
    expect(PUB).toMatch(/^[0-9a-f]{64}$/);
  });
});
