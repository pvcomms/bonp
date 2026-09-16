import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

import { canonicalJSON, CanonicalizationError } from "../src/canonical.js";
import { canonicalize, envelopeId } from "../src/envelope.js";
import type { BiometricEnvelope } from "../src/types.js";

/** The BONP-1.0 canonicalizer, preserved so the defect stays testable. */
function bonp10Canonicalize(value: object): string {
  return JSON.stringify(value, Object.keys(value).sort() as never);
}

function envelope(overrides: {
  metric?: string;
  value?: number;
  subjectId?: string;
}): BiometricEnvelope {
  return {
    version: "BONP-1.0",
    claim: {
      metric: (overrides.metric ?? "recovery_score") as never,
      value: overrides.value ?? 17,
      timestamp: "2026-04-19T06:00:00Z",
      window: { start: "2026-04-18T06:00:00Z", end: "2026-04-19T06:00:00Z" },
      device: { provider: "whoop" as never, model: "4.0" },
      subject: { id: overrides.subjectId ?? "subject-a", data_hash: "abc123" },
    },
    attestation: {
      adapter_id: "whoop-v1",
      nonce: "0".repeat(64),
      fetch_timestamp: "2026-04-19T06:00:05Z",
      provider_public_key: "f".repeat(64),
      provider_signature: "a".repeat(128),
    },
    settlement: {
      staleness_window_ms: 60_000,
      confidence_score: 0.95,
      dispute_window_ms: 3_600_000,
    },
  } as BiometricEnvelope;
}

describe("the BONP-1.0 canonicalization defect", () => {
  // These two tests document why 1.1 exists. If either ever fails, the
  // history in ERRATA.md is wrong and should be corrected.

  it("erased every nested object, because the replacer is a key allow-list", () => {
    const serialized = bonp10Canonicalize(envelope({}));
    expect(serialized).toBe(
      '{"attestation":{},"claim":{},"settlement":{},"version":"BONP-1.0"}',
    );
  });

  it("gave two unrelated claims the same envelope id", () => {
    const mine = bonp10Canonicalize(
      envelope({ metric: "recovery_score", value: 17, subjectId: "param" }),
    );
    const theirs = bonp10Canonicalize(
      envelope({ metric: "strain", value: 99, subjectId: "someone-else" }),
    );

    const id = (s: string) => createHash("sha256").update(s).digest("hex");
    expect(id(mine)).toBe(id(theirs));
  });
});

describe("canonicalJSON", () => {
  it("sorts keys at every nesting level, not just the top", () => {
    const nested = { b: 1, a: { d: 2, c: { f: 3, e: 4 } } };
    expect(canonicalJSON(nested)).toBe('{"a":{"c":{"e":4,"f":3},"d":2},"b":1}');
  });

  it("is order-independent for objects but order-preserving for arrays", () => {
    expect(canonicalJSON({ a: 1, b: 2 })).toBe(canonicalJSON({ b: 2, a: 1 }));
    expect(canonicalJSON([1, 2])).not.toBe(canonicalJSON([2, 1]));
  });

  it("emits no whitespace", () => {
    expect(canonicalJSON({ a: [1, { b: 2 }] })).toBe('{"a":[1,{"b":2}]}');
  });

  it("drops undefined properties but keeps null", () => {
    expect(canonicalJSON({ a: undefined, b: null })).toBe('{"b":null}');
  });

  it("renders undefined array elements as null, matching JSON.stringify", () => {
    expect(canonicalJSON([1, undefined, 3])).toBe("[1,null,3]");
  });

  it("normalises negative zero", () => {
    expect(canonicalJSON({ v: -0 })).toBe('{"v":0}');
  });

  it("escapes control characters and quotes", () => {
    expect(canonicalJSON({ s: 'a"b\\c\nd' })).toBe(
      '{"s":"a\\"b\\\\c\\nd\\u0001"}',
    );
  });

  it("leaves non-ASCII characters literal", () => {
    expect(canonicalJSON({ s: "書斎" })).toBe('{"s":"書斎"}');
  });

  it("sorts by UTF-16 code unit, so uppercase precedes lowercase", () => {
    expect(canonicalJSON({ a: 1, B: 2, A: 3 })).toBe('{"A":3,"B":2,"a":1}');
  });

  it("round-trips through JSON.parse unchanged", () => {
    const value = { z: [1, "two", null, { y: true }], a: -0.5 };
    expect(JSON.parse(canonicalJSON(value))).toEqual(
      JSON.parse(JSON.stringify(value)),
    );
  });

  it("rejects values that cannot serialize deterministically", () => {
    expect(() => canonicalJSON({ v: NaN })).toThrow(CanonicalizationError);
    expect(() => canonicalJSON({ v: Infinity })).toThrow(CanonicalizationError);
    expect(() => canonicalJSON({ v: 1n })).toThrow(CanonicalizationError);
    expect(() => canonicalJSON({ v: new Date() })).toThrow(
      CanonicalizationError,
    );
    expect(() => canonicalJSON({ v: () => {} })).toThrow(CanonicalizationError);
  });

  it("names the path to the offending value", () => {
    expect(() => canonicalJSON({ claim: { window: { start: NaN } } })).toThrow(
      /\$\.claim\.window\.start/,
    );
  });

  it("rejects circular references instead of overflowing the stack", () => {
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic.self = cyclic;
    expect(() => canonicalJSON(cyclic)).toThrow(/circular/);
  });

  it("allows the same object to appear twice in one document", () => {
    const shared = { x: 1 };
    expect(canonicalJSON({ a: shared, b: shared })).toBe(
      '{"a":{"x":1},"b":{"x":1}}',
    );
  });
});

describe("envelopeId", () => {
  it("differs when the claim differs", () => {
    expect(envelopeId(envelope({ value: 17 }))).not.toBe(
      envelopeId(envelope({ value: 99 })),
    );
  });

  it("differs when only a deeply nested field differs", () => {
    expect(envelopeId(envelope({ subjectId: "a" }))).not.toBe(
      envelopeId(envelope({ subjectId: "b" })),
    );
  });

  it("is stable across key insertion order", () => {
    const a = envelope({});
    const reordered = JSON.parse(
      JSON.stringify({
        settlement: a.settlement,
        claim: a.claim,
        attestation: a.attestation,
        version: a.version,
      }),
    ) as BiometricEnvelope;
    expect(envelopeId(reordered)).toBe(envelopeId(a));
  });

  it("is a 64-character hex digest", () => {
    expect(envelopeId(envelope({}))).toMatch(/^[0-9a-f]{64}$/);
  });

  it("preserves the full payload through canonicalization", () => {
    const serialized = canonicalize(envelope({ value: 17 }));
    expect(serialized).toContain('"value":17');
    expect(serialized).toContain('"metric":"recovery_score"');
    expect(serialized).not.toContain('"claim":{}');
  });
});
