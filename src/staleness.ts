import type { BiometricEnvelope, StalenessProof } from "./types.js";
import { envelopeId } from "./envelope.js";

export function generateStalenessProof(
  envelope: BiometricEnvelope,
  now?: Date,
): StalenessProof {
  const reference = now ?? new Date();
  const claimedTs = new Date(envelope.claim.timestamp).getTime();
  const fetchTs = new Date(envelope.attestation.fetch_timestamp).getTime();
  const lagMs = fetchTs - claimedTs;
  const maxAgeMs = envelope.settlement.staleness_window_ms;
  const ageFromNowMs = reference.getTime() - claimedTs;

  return {
    envelope_id: envelopeId(envelope),
    claimed_timestamp: envelope.claim.timestamp,
    fetch_timestamp: envelope.attestation.fetch_timestamp,
    max_age_ms: maxAgeMs,
    is_fresh: lagMs <= maxAgeMs && ageFromNowMs <= maxAgeMs,
    lag_ms: lagMs,
  };
}

export function checkFreshness(
  envelope: BiometricEnvelope,
  now?: Date,
): boolean {
  return generateStalenessProof(envelope, now).is_fresh;
}

/**
 * Given multiple envelopes for the same metric, returns the one with the
 * most recent claim timestamp that is still within its staleness window.
 * Throws if no fresh envelope exists.
 */
export function freshestValidEnvelope(
  envelopes: BiometricEnvelope[],
  now?: Date,
): BiometricEnvelope {
  const reference = now ?? new Date();

  const fresh = envelopes
    .filter((e) => checkFreshness(e, reference))
    .sort(
      (a, b) =>
        new Date(b.claim.timestamp).getTime() -
        new Date(a.claim.timestamp).getTime(),
    );

  if (fresh.length === 0) {
    throw new Error("No fresh envelopes available within staleness window");
  }

  return fresh[0];
}
