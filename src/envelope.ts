import { createHash, randomBytes } from "crypto";
import { canonicalJSON } from "./canonical.js";
import { verifyClaim } from "./signature.js";
import type {
  BiometricEnvelope,
  BiometricClaim,
  BiometricAttestation,
  SettlementMetadata,
  BONPError,
} from "./types.js";

// In-memory nonce registry — swap for Redis in production
const usedNonces = new Set<string>();

export function createEnvelope(
  claim: BiometricClaim,
  attestation: BiometricAttestation,
  settlement: SettlementMetadata,
): BiometricEnvelope {
  return {
    version: "BONP-1.0",
    claim,
    attestation,
    settlement,
  };
}

/**
 * Canonical serialization of a full envelope (RFC 8785).
 *
 * BONP-1.0 used `JSON.stringify(envelope, Object.keys(envelope).sort())`,
 * which flattened every nested object to {} and made this function
 * constant across all envelopes. See ERRATA.md.
 */
export function canonicalize(envelope: BiometricEnvelope): string {
  return canonicalJSON(envelope);
}

/**
 * Canonical serialization of the claim alone — the signed message.
 *
 * SPEC §3.2 signs over this, not over the whole envelope, so that the
 * attestation and settlement metadata can be amended without
 * invalidating the subject's signature.
 */
export function canonicalizeClaim(claim: BiometricClaim): string {
  return canonicalJSON(claim);
}

export function envelopeId(envelope: BiometricEnvelope): string {
  return createHash("sha256")
    .update(canonicalize(envelope), "utf8")
    .digest("hex");
}

export function generateNonce(): string {
  return randomBytes(32).toString("hex");
}

export async function verifyEnvelope(
  envelope: BiometricEnvelope,
): Promise<{ valid: boolean; errors: BONPError[] }> {
  const errors: BONPError[] = [];

  // 1. Version + structural check
  if (!envelope || envelope.version !== "BONP-1.0") {
    errors.push({ code: "BONP-001", message: "Invalid envelope format" });
    return { valid: false, errors };
  }

  const { claim, attestation, settlement } = envelope;

  if (
    !claim?.metric ||
    claim.value === undefined ||
    !claim.timestamp ||
    !claim.window?.start ||
    !claim.window?.end ||
    !claim.device?.provider ||
    !claim.subject?.id ||
    !claim.subject?.data_hash
  ) {
    errors.push({ code: "BONP-001", message: "Invalid envelope format" });
  }

  if (
    !attestation?.adapter_id ||
    !attestation?.nonce ||
    !attestation?.fetch_timestamp ||
    !attestation?.provider_public_key
  ) {
    errors.push({ code: "BONP-001", message: "Invalid envelope format" });
  }

  if (
    settlement?.staleness_window_ms === undefined ||
    settlement?.confidence_score === undefined ||
    settlement?.dispute_window_ms === undefined
  ) {
    errors.push({ code: "BONP-001", message: "Invalid envelope format" });
  }

  if (errors.length > 0) return { valid: false, errors };

  // 2. Replay protection
  if (usedNonces.has(attestation.nonce)) {
    errors.push({
      code: "BONP-004",
      message: "Replay detected: nonce already used",
    });
  } else {
    usedNonces.add(attestation.nonce);
  }

  // 3. Staleness check
  const fetchTime = new Date(attestation.fetch_timestamp).getTime();
  const claimTime = new Date(claim.timestamp).getTime();
  const lagMs = fetchTime - claimTime;
  if (lagMs > settlement.staleness_window_ms) {
    errors.push({
      code: "BONP-003",
      message: "Stale data: outside staleness window",
    });
  }

  // 4. Confidence floor (0.5 minimum)
  if (settlement.confidence_score < 0.5) {
    errors.push({ code: "BONP-008", message: "Insufficient confidence score" });
  }

  // 5. Signature verification (adapter-signed; provider-native in v2).
  // The public key travels in the envelope, so this proves the claim was
  // not altered after signing — not that the signer is who they say they
  // are. Binding adapter_id to a known key is the verifier's job; see
  // SPEC §3.4 and the trust-model caveat in the README.
  if (!attestation.provider_signature) {
    errors.push({ code: "BONP-002", message: "Signature verification failed" });
  } else if (
    !verifyClaim(
      claim,
      attestation.provider_signature,
      attestation.provider_public_key,
    )
  ) {
    // BONP-002's message is normative (SPEC §5), so the detail goes in
    // `detail` rather than being spliced into the wire-visible string.
    errors.push({
      code: "BONP-002",
      message: "Signature verification failed",
      detail:
        "claim does not match provider_signature under provider_public_key",
    });
  }

  return { valid: errors.length === 0, errors };
}

/** Clear the nonce registry — test use only */
export function _resetNonceRegistry(): void {
  usedNonces.clear();
}
