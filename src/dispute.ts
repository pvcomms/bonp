import type {
  BiometricEnvelope,
  DisputeRecord,
  DisputeStatus,
} from "./types.js";
import { envelopeId } from "./envelope.js";
import { createHash } from "crypto";

export function openDispute(
  envelope: BiometricEnvelope,
  challengerId: string,
): DisputeRecord {
  const now = new Date();
  const disputeWindowMs = envelope.settlement.dispute_window_ms;
  const fetchTime = new Date(envelope.attestation.fetch_timestamp).getTime();

  if (now.getTime() > fetchTime + disputeWindowMs) {
    throw Object.assign(new Error("Dispute window has expired"), {
      code: "BONP-007",
    });
  }

  return {
    envelope_id: envelopeId(envelope),
    challenger_id: createHash("sha256").update(challengerId).digest("hex"),
    challenge_evidence: [],
    status: "open",
    opened_at: now.toISOString(),
  };
}

export function submitEvidence(
  dispute: DisputeRecord,
  counterEnvelopes: BiometricEnvelope[],
): DisputeRecord {
  if (dispute.status !== "open") {
    throw new Error(`Cannot submit evidence: dispute is ${dispute.status}`);
  }
  return {
    ...dispute,
    challenge_evidence: [...dispute.challenge_evidence, ...counterEnvelopes],
  };
}

export function resolveDispute(
  dispute: DisputeRecord,
  decision: "resolved_for_claimant" | "resolved_for_challenger",
  reason: string,
): DisputeRecord {
  if (dispute.status !== "open") {
    throw new Error(`Cannot resolve dispute: already ${dispute.status}`);
  }
  return {
    ...dispute,
    status: decision,
    resolved_at: new Date().toISOString(),
    resolution_reason: reason,
  };
}

export function isDisputeExpired(
  dispute: DisputeRecord,
  disputeWindowMs: number,
): boolean {
  const openedAt = new Date(dispute.opened_at).getTime();
  return Date.now() > openedAt + disputeWindowMs;
}

/**
 * Heuristic adjudication:
 * If challenger evidence has higher confidence AND same provider → resolve for challenger.
 * If no evidence submitted → resolve for claimant.
 * Otherwise → needs manual review (returns "open").
 */
export function adjudicate(
  dispute: DisputeRecord,
  originalEnvelope: BiometricEnvelope,
): DisputeStatus {
  if (dispute.status !== "open") return dispute.status;

  if (dispute.challenge_evidence.length === 0) {
    return "resolved_for_claimant";
  }

  // Find best counter-envelope from same provider
  const originalProvider = originalEnvelope.claim.device.provider;
  const originalConfidence = originalEnvelope.settlement.confidence_score;

  const bestCounter = dispute.challenge_evidence
    .filter((e) => e.claim.device.provider === originalProvider)
    .sort(
      (a, b) => b.settlement.confidence_score - a.settlement.confidence_score,
    )[0];

  if (!bestCounter) {
    // Counter evidence from a different provider — inconclusive, needs manual review
    return "open";
  }

  if (bestCounter.settlement.confidence_score > originalConfidence) {
    return "resolved_for_challenger";
  }

  return "resolved_for_claimant";
}
