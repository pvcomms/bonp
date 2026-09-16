# BONP-1: Biometric Oracle Network Protocol

**Status:** Draft  
**Version:** 1.0.0  
**Created:** 2026-04-19  
**Authors:** Param Vaswani, Claude Code

---

## Abstract

BONP-1 defines a standard data format and verification protocol for using consumer biometric device data as settlement oracles in prediction markets and commitment contracts. It specifies a signed envelope format (`BiometricEnvelope`) that wraps a biometric measurement claim with cryptographic attestation, staleness proofs, and dispute metadata. The protocol is device-agnostic, implemented through typed adapters that normalize provider-specific APIs into a common claim structure. BONP-1 addresses three gaps in current biometric oracle deployments: lack of a shared data model, no replay or staleness protection, and no standard dispute pathway.

---

## Motivation

Prediction markets that settle on biometric data face a structural problem: every implementation reinvents the oracle layer. A commitment market using Whoop recovery scores and one using Oura readiness use incompatible data fetching, no shared trust model, and cannot interoperate. Three specific deficiencies recur:

1. **Fragmentation.** Each market writes bespoke adapter code against device APIs. Field mappings, unit conversions, and error handling are duplicated without a canonical reference.

2. **No trust model.** Raw API responses from device providers carry no cryptographic attestation. An oracle can submit any value without proof that it was fetched at a specific time from a specific account.

3. **No replay protection.** Without nonces and signed fetch timestamps, an attacker can replay a favorable historical measurement to settle a current market.

BONP-1 solves these with a standard signed envelope, a typed adapter interface, and a formal dispute pathway. It does not require on-chain infrastructure — it is a data protocol, not a blockchain protocol. Contracts and markets that want on-chain settlement can verify BONP envelopes independently.

---

## Specification

### 1. Data Types

#### 1.1 `BiometricProvider`

```typescript
type BiometricProvider =
  | "whoop"
  | "oura"
  | "garmin"
  | "apple_health"
  | "ultrahuman";
```

#### 1.2 `BiometricMetric`

Canonical metric identifiers. All adapters MUST map provider-specific fields to these identifiers.

| Identifier           | Description               | Unit        |
| -------------------- | ------------------------- | ----------- |
| `recovery_score`     | Whoop recovery score      | 0–100       |
| `hrv_rmssd`          | Heart rate variability    | ms          |
| `sleep_performance`  | Sleep quality score       | 0–100       |
| `sleep_hours`        | Total sleep duration      | hours       |
| `resting_heart_rate` | Resting HR                | bpm         |
| `strain`             | Whoop exertion score      | 0–21        |
| `readiness_score`    | Oura readiness score      | 0–100       |
| `spo2`               | Blood oxygen saturation   | percent     |
| `respiratory_rate`   | Breathing rate            | breaths/min |
| `step_count`         | Steps in window           | steps       |
| `active_calories`    | Active energy expenditure | kcal        |

#### 1.3 `BiometricWindow`

```typescript
interface BiometricWindow {
  start: string; // ISO 8601 UTC
  end: string; // ISO 8601 UTC
}
```

Both fields MUST be ISO 8601 strings with UTC timezone. Rolling windows SHOULD use the start of the calendar day in the subject's local timezone, converted to UTC.

#### 1.4 `BiometricClaim`

The core measurement assertion:

```typescript
interface BiometricClaim {
  metric: BiometricMetric;
  value: number;
  unit: string;
  timestamp: string; // ISO 8601 — when measurement was taken
  window: BiometricWindow;
  device: {
    provider: BiometricProvider;
    device_id: string; // SHA-256 of provider's internal device ID
    model?: string;
  };
  subject: {
    id: string; // SHA-256 of provider's user ID
    data_hash: string; // SHA-256 of raw provider API response body
  };
}
```

`subject.id` MUST be a SHA-256 hash of the provider's user identifier. Raw user IDs MUST NOT appear in envelopes. `subject.data_hash` enables independent verification that the reported value matches the original provider response.

#### 1.5 `BiometricAttestation`

```typescript
interface BiometricAttestation {
  provider_signature: string; // hex-encoded Ed25519 signature
  provider_public_key: string; // hex-encoded Ed25519 public key
  adapter_id: string; // e.g. "bonp-whoop-v1"
  adapter_version: string; // semver
  fetch_timestamp: string; // ISO 8601 UTC — when oracle fetched
  nonce: string; // 32-byte hex — for replay protection
}
```

In BONP v1, the signature is produced by the **adapter's** Ed25519 keypair, not the device provider's. The signed message is the canonical JSON serialization of `BiometricClaim` (see §3.1). BONP v2 will require provider-native signatures when device manufacturers expose signing infrastructure.

#### 1.6 `SettlementMetadata`

```typescript
interface SettlementMetadata {
  staleness_window_ms: number; // max acceptable data age at settlement time
  confidence_score: number; // 0.0–1.0
  dispute_window_ms: number; // time after fetch during which disputes are valid
  arbiter_address?: string; // optional Ethereum address for on-chain arbitration
}
```

Recommended defaults by provider:

| Provider     | `staleness_window_ms` | `confidence_score` | `dispute_window_ms` |
| ------------ | --------------------- | ------------------ | ------------------- |
| Whoop        | 43200000 (12h)        | 0.95               | 86400000 (24h)      |
| Oura         | 86400000 (24h)        | 0.93               | 86400000 (24h)      |
| Apple Health | 172800000 (48h)       | 0.88               | 86400000 (24h)      |

#### 1.7 `BiometricEnvelope`

The top-level BONP data structure:

```typescript
interface BiometricEnvelope {
  version: "BONP-1.0";
  claim: BiometricClaim;
  attestation: BiometricAttestation;
  settlement: SettlementMetadata;
}
```

`version` MUST be the literal string `"BONP-1.0"`. Future protocol versions will use a new version string. Parsers MUST reject envelopes with unrecognized version strings.

#### 1.8 `DisputeRecord`

```typescript
type DisputeStatus =
  | "open"
  | "resolved_for_claimant"
  | "resolved_for_challenger"
  | "expired";

interface DisputeRecord {
  envelope_id: string; // SHA-256 of canonical envelope JSON
  challenger_id: string; // SHA-256 of challenger's identifier
  challenge_evidence: BiometricEnvelope[];
  manual_attestation?: string; // signed free-text statement
  status: DisputeStatus;
  opened_at: string; // ISO 8601
  resolved_at?: string;
  resolution_reason?: string;
}
```

#### 1.9 `StalenessProof`

```typescript
interface StalenessProof {
  envelope_id: string;
  claimed_timestamp: string;
  fetch_timestamp: string;
  max_age_ms: number;
  is_fresh: boolean;
  lag_ms: number; // fetch_timestamp − claimed_timestamp
}
```

`is_fresh` is `true` iff `lag_ms ≤ max_age_ms` AND `(now − claimed_timestamp) ≤ max_age_ms`.

---

### 2. Error Codes

| Code     | Meaning                              | Recovery                            |
| -------- | ------------------------------------ | ----------------------------------- |
| BONP-001 | Invalid envelope format              | Fix malformed fields                |
| BONP-002 | Signature verification failed        | Re-fetch with valid adapter keypair |
| BONP-003 | Stale data: outside staleness window | Re-fetch with current timestamp     |
| BONP-004 | Replay detected: nonce already used  | Generate new nonce                  |
| BONP-005 | Provider authentication failed       | Refresh OAuth token                 |
| BONP-006 | Metric not supported by adapter      | Use supported metric                |
| BONP-007 | Dispute window expired               | No remedy; settlement is final      |
| BONP-008 | Insufficient confidence score        | Use higher-confidence adapter       |

---

### 3. Algorithms

#### 3.1 Canonical Serialization

The canonical form of a `BiometricClaim` for signing is produced by:

1. Serializing the claim object to JSON with **lexicographically sorted keys** at every nesting level.
2. No extra whitespace (compact form).
3. UTF-8 encoding.

```typescript
function canonicalizeClaim(claim: BiometricClaim): string {
  return canonicalJSON(claim); // RFC 8785, see src/canonical.ts
}
```

> **Erratum BONP-1.0-E1.** Versions up to 1.0 specified this as
> `JSON.stringify(claim, Object.keys(claim).sort())`. That is a *replacer*
> array, not a key sort: it acts as an allow-list at every nesting depth and
> erases all nested objects, making `envelope_id` constant and every
> signature interchangeable. See [ERRATA.md](ERRATA.md). Reject
> `version: "BONP-1.0"`.

The `envelope_id` is SHA-256 of the canonical JSON of the full `BiometricEnvelope`.

#### 3.2 Signature Production (v1)

```
msg    = canonicalizeClaim(envelope.claim)   // UTF-8 bytes
sig    = Ed25519.sign(msg, adapter_private_key)
stored = hex(sig)
```

The `provider_public_key` field stores the corresponding public key in hex. This key is controlled by the adapter operator in v1.

#### 3.3 Replay Protection

Each adapter MUST generate a cryptographically random 32-byte nonce per envelope. Verifiers MUST maintain a nonce registry and reject envelopes whose nonce has been seen before. In-memory registries are acceptable for single-process deployments; production deployments SHOULD use a distributed store (e.g. Redis with TTL = `dispute_window_ms`).

#### 3.4 Staleness Verification

```
lag_ms = parse(fetch_timestamp) − parse(claim.timestamp)
age_ms = now − parse(claim.timestamp)
is_fresh = lag_ms ≤ staleness_window_ms AND age_ms ≤ staleness_window_ms
```

Both conditions must hold. A data point fetched immediately but presented for settlement 48 hours later is stale even if `lag_ms` is small.

---

### 4. Settlement Lifecycle

```
┌─────────────┐     fetchMetric()      ┌──────────────────┐
│   Market    │ ──────────────────────▶│  Adapter (Oracle) │
│  Contract   │                        │  (Whoop/Oura/AH)  │
└─────────────┘                        └──────────────────┘
       │                                        │
       │  ◀── BiometricEnvelope ────────────────┘
       │
       │  verifyEnvelope()
       │    ├─ version check
       │    ├─ required fields
       │    ├─ nonce registry check
       │    ├─ staleness check
       │    └─ signature check
       │
       ▼
  [valid = true]
       │
       │  generateStalenessProof()
       │    └─ is_fresh = true?
       │
       ▼
  Settlement submitted
       │
       │  ← dispute_window_ms begins →
       │
  ┌────▼──────┐
  │  Dispute? │──── no ──▶ Settlement final
  └────┬──────┘
       │ yes
       ▼
  openDispute()
  submitEvidence()
  adjudicate() / resolveDispute()
       │
       ▼
  Resolution recorded
```

**Phases:**

1. **Fetch.** Oracle calls `adapter.fetchMetric(userId, metric, range, { access_token })`. The adapter fetches from the provider API and wraps the response in a signed `BiometricEnvelope`.

2. **Submit.** The envelope is submitted to the market contract or off-chain settlement engine.

3. **Verify.** Settlement engine calls `verifyEnvelope(envelope)`. Any BONP error aborts settlement.

4. **Challenge period.** After submission, `dispute_window_ms` elapses. During this window, any party with counter-evidence may call `openDispute()` and `submitEvidence()`.

5. **Resolve.** After challenge period with no dispute, settlement is final. If disputed, an arbiter (heuristic or human) calls `resolveDispute()`.

---

### 5. Adapter Interface

All adapters MUST implement:

```typescript
interface BiometricAdapter {
  readonly id: string; // e.g. "bonp-whoop-v1"
  readonly version: string; // semver
  readonly provider: BiometricProvider;

  getCapabilities(): AdapterCapabilities;
  fetchMetric(userId, metric, range, options?): Promise<BiometricEnvelope>;
  verifySignature(envelope): Promise<boolean>;
  getPublicKey(): string;
}
```

Adapters MUST:

- Generate a fresh nonce per envelope.
- Record `fetch_timestamp` as the time the API response was received, not the time `fetchMetric` was called.
- Include `data_hash = SHA-256(raw_response_body)` in `claim.subject`.
- Throw a structured error with `code: "BONP-006"` for unsupported metrics.
- Throw a structured error with `code: "BONP-005"` on provider auth failures.

Adapters MUST NOT:

- Log or persist raw access tokens.
- Return synthetic or cached data without clearly marking `confidence_score < 0.5`.
- Reuse nonces.

---

### 6. Dispute Resolution

Disputes are initiated by parties with counter-evidence. The heuristic adjudication algorithm is:

1. If `challenge_evidence` is empty → `resolved_for_claimant`.
2. If counter-envelopes exist from a **different** provider → `open` (needs manual review).
3. If counter-envelopes exist from the **same** provider with `confidence_score > original.confidence_score` → `resolved_for_challenger`.
4. Otherwise → `resolved_for_claimant`.

Human arbiters MAY override heuristic results by calling `resolveDispute()` directly with a `resolution_reason`.

---

## Rationale

**Why Ed25519?** Ed25519 signatures are compact (64 bytes), fast to verify, and have no parameter-choice vulnerabilities unlike RSA or ECDSA with secp256k1. The `@noble/ed25519` library provides a pure-TypeScript implementation with no native dependencies and audited security.

**Why JSON and not binary (e.g. protobuf)?** Consumer device APIs return JSON. Adding a binary serialization layer introduces a transcription step that is itself a source of bugs and disputes. JSON is auditable by anyone with a text editor, which matters for a trust-minimized oracle. The `data_hash` field lets anyone who obtains the raw API response independently verify the claim.

**Why rolling windows and not point-in-time?** Biometric measurements are inherently windowed — recovery scores aggregate the prior night's sleep, step counts accumulate over a day. Point-in-time semantics create ambiguity about which measurement "counts" when a provider returns multiple records. Windows make the relevant period explicit and auditable.

**Why adapter-signed in v1?** Device providers (Whoop, Oura, Apple) do not currently sign their API responses. Until they do, the adapter is the trust anchor. Users who need stronger guarantees can run their own adapter with a key they control and self-custody the private key. BONP v2 will define a provider-native signature extension point.

**Why separate `staleness_window_ms` and `dispute_window_ms`?** Staleness governs data quality (how old is this measurement?). Dispute windows govern process (how long can the settlement be challenged?). They have different purposes and different appropriate values. A Whoop recovery score is stale after 12 hours but a dispute window of 24 hours is appropriate for human review latency.

---

## Security Considerations

**Adapter key custody.** In v1, the adapter signs envelopes with a key it controls. Compromise of the adapter signing key allows forged envelopes. Operators SHOULD store adapter keys in HSMs or cloud KMS (AWS KMS, GCP Cloud KMS) and rotate quarterly.

**OAuth token exposure.** Access tokens passed to `fetchMetric()` MUST NOT be logged or persisted. Adapters SHOULD zero out token memory after use (this is a best-effort in managed runtimes).

**Collusion.** A malicious oracle operator could collude with a market participant to submit favorable data. Dispute windows and `data_hash` verification mitigate but do not eliminate this. Markets SHOULD use multiple independent oracle operators for high-value settlements.

**Rate limiting and DoS.** Adapters call third-party APIs with user credentials. Excessive settlement attempts could exhaust provider API quotas. Markets SHOULD rate-limit settlement calls per user per day.

**Subject ID privacy.** `subject.id` is a SHA-256 hash of the provider's user ID. This prevents PII exposure in envelopes but does not prevent re-identification if the provider's user ID is known. Markets SHOULD add a per-market salt: `SHA-256(userId + marketId + staticSalt)`.

**Nonce registry TTL.** In-memory nonce registries are lost on process restart. Replays are possible across restarts. Production deployments MUST use a persistent store with TTL ≥ `dispute_window_ms`.

---

## Reference Implementations

| Adapter      | File                           | Provider API                          |
| ------------ | ------------------------------ | ------------------------------------- |
| Whoop        | `src/adapters/whoop.ts`        | `api.prod.whoop.com/developer/v1`     |
| Oura         | `src/adapters/oura.ts`         | `api.ouraring.com/v2/usercollection`  |
| Apple Health | `src/adapters/apple-health.ts` | HealthKit export XML / HealthKit push |

---

## Copyright

Copyright 2026 Param Vaswani. Licensed under MIT. This specification is provided as-is without warranty of any kind.
