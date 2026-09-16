export type BiometricProvider =
  | "whoop"
  | "oura"
  | "garmin"
  | "apple_health"
  | "ultrahuman";

export type BiometricMetric =
  | "recovery_score"
  | "hrv_rmssd"
  | "sleep_performance"
  | "sleep_hours"
  | "resting_heart_rate"
  | "strain"
  | "readiness_score"
  | "spo2"
  | "respiratory_rate"
  | "step_count"
  | "active_calories";

export interface BiometricWindow {
  start: string; // ISO 8601
  end: string;
}

export interface BiometricClaim {
  metric: BiometricMetric;
  value: number;
  unit: string;
  timestamp: string; // when measurement was taken
  window: BiometricWindow;
  device: {
    provider: BiometricProvider;
    device_id: string; // hashed, opaque
    model?: string;
  };
  subject: {
    id: string; // hashed user ID (not PII)
    data_hash: string; // SHA-256 of raw provider response
  };
}

export interface BiometricAttestation {
  provider_signature: string; // hex Ed25519
  provider_public_key: string; // hex Ed25519 public key
  adapter_id: string; // e.g. "bonp-whoop-v1"
  adapter_version: string; // semver
  fetch_timestamp: string; // ISO 8601 — when oracle fetched
  nonce: string; // 32-byte hex for replay protection
}

export interface SettlementMetadata {
  staleness_window_ms: number; // data age limit for valid settlement
  confidence_score: number; // 0.0–1.0
  dispute_window_ms: number; // e.g. 86400000 (24h)
  arbiter_address?: string; // optional: Ethereum address for on-chain arbitration
}

export interface BiometricEnvelope {
  version: "BONP-1.0";
  claim: BiometricClaim;
  attestation: BiometricAttestation;
  settlement: SettlementMetadata;
}

export type DisputeStatus =
  | "open"
  | "resolved_for_claimant"
  | "resolved_for_challenger"
  | "expired";

export interface DisputeRecord {
  envelope_id: string; // SHA-256 of envelope JSON
  challenger_id: string; // hashed challenger ID
  challenge_evidence: BiometricEnvelope[]; // counter-envelopes
  manual_attestation?: string; // signed statement
  status: DisputeStatus;
  opened_at: string;
  resolved_at?: string;
  resolution_reason?: string;
}

export interface StalenessProof {
  envelope_id: string;
  claimed_timestamp: string;
  fetch_timestamp: string;
  max_age_ms: number;
  is_fresh: boolean;
  lag_ms: number; // fetch_timestamp - claimed_timestamp
}

/**
 * Normative error codes (SPEC §5). `message` is fixed per code so that
 * verifiers can match on it; anything implementation-specific goes in
 * the optional `detail`, which is advisory and never load-bearing.
 */
export type BONPError = (
  | { code: "BONP-001"; message: "Invalid envelope format" }
  | { code: "BONP-002"; message: "Signature verification failed" }
  | { code: "BONP-003"; message: "Stale data: outside staleness window" }
  | { code: "BONP-004"; message: "Replay detected: nonce already used" }
  | { code: "BONP-005"; message: "Provider authentication failed" }
  | { code: "BONP-006"; message: "Metric not supported by adapter" }
  | { code: "BONP-007"; message: "Dispute window expired" }
  | { code: "BONP-008"; message: "Insufficient confidence score" }
) & { detail?: string };
