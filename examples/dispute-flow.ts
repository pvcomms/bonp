/**
 * Example: disputing a settlement using BONP
 *
 * Scenario: Alice submitted a recovery_score=45 settlement (market failed).
 * Bob (challenger) has counter-evidence showing recovery_score=72 from the
 * same Whoop account — possibly a sync timing issue. He opens a dispute.
 */
import {
  openDispute,
  submitEvidence,
  adjudicate,
  resolveDispute,
  isDisputeExpired,
  generateStalenessProof,
  type BiometricEnvelope,
  type DisputeRecord,
} from "../src/index.js";

function demonstrateDisputeFlow(
  originalEnvelope: BiometricEnvelope,
  counterEnvelope: BiometricEnvelope,
): void {
  const challengerId = "user-bob-challenger";

  // 1. Open dispute — will throw BONP-007 if window expired
  let dispute: DisputeRecord;
  try {
    dispute = openDispute(originalEnvelope, challengerId);
    console.log(`Dispute opened: ${dispute.envelope_id}`);
    console.log(`  status: ${dispute.status}`);
    console.log(`  opened_at: ${dispute.opened_at}`);
  } catch (err: unknown) {
    const e = err as Error & { code?: string };
    console.error(`Cannot open dispute: ${e.message} [${e.code}]`);
    return;
  }

  // 2. Check if it's expired before submitting evidence
  const windowMs = originalEnvelope.settlement.dispute_window_ms;
  if (isDisputeExpired(dispute, windowMs)) {
    console.log("Dispute expired before evidence could be submitted");
    return;
  }

  // 3. Submit counter-evidence
  dispute = submitEvidence(dispute, [counterEnvelope]);
  console.log(
    `Evidence submitted: ${dispute.challenge_evidence.length} envelope(s)`,
  );

  // 4. Run heuristic adjudication
  const heuristicResult = adjudicate(dispute, originalEnvelope);
  console.log(`Heuristic result: ${heuristicResult}`);

  // 5. Resolve (in production, an arbiter or on-chain contract calls this)
  const resolved = resolveDispute(
    dispute,
    heuristicResult === "resolved_for_challenger"
      ? "resolved_for_challenger"
      : "resolved_for_claimant",
    heuristicResult === "resolved_for_challenger"
      ? "Counter-envelope has higher confidence score from same provider"
      : "Original envelope confidence exceeds challenger evidence",
  );

  console.log(`Dispute resolved: ${resolved.status}`);
  console.log(`  reason: ${resolved.resolution_reason}`);
  console.log(`  resolved_at: ${resolved.resolved_at}`);
}

// To run this example, pass real envelopes fetched via adapter.fetchMetric()
// demonstrateDisputeFlow(originalEnvelope, counterEnvelope);
