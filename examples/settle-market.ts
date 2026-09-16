/**
 * Example: settling a Keep market using BONP
 *
 * This shows the exact pattern Keep's settlement engine uses:
 * fetch → verify → staleness-check → resolve.
 */
import {
  WhoopAdapter,
  AdapterRegistry,
  verifyEnvelope,
  generateStalenessProof,
} from "../src/index.js";

async function settleMarket(
  marketId: string,
  userId: string,
  accessToken: string,
): Promise<void> {
  const registry = new AdapterRegistry();
  registry.register(new WhoopAdapter());

  const adapter = registry.get("whoop");
  if (!adapter) throw new Error("Whoop adapter not registered");

  // Fetch oracle data for the commitment window
  const envelope = await adapter.fetchMetric(
    userId,
    "recovery_score",
    {
      start: new Date("2026-04-19T00:00:00Z"),
      end: new Date("2026-04-20T00:00:00Z"),
    },
    { access_token: accessToken },
  );

  // Structural + replay + staleness verification
  const { valid, errors } = await verifyEnvelope(envelope);
  if (!valid) {
    throw new Error(
      `Invalid oracle data: ${errors.map((e) => e.code).join(", ")}`,
    );
  }

  // Explicit freshness proof — log it for audit trail
  const staleness = generateStalenessProof(envelope);
  if (!staleness.is_fresh) {
    throw new Error(
      `Stale data rejected: ${staleness.lag_ms}ms lag exceeds ${staleness.max_age_ms}ms window`,
    );
  }

  const score = envelope.claim.value;
  const passed = score >= 70; // example threshold: recovery >= 70

  console.log(`Market ${marketId} settlement:`);
  console.log(`  recovery_score = ${score}`);
  console.log(`  threshold = 70`);
  console.log(`  result = ${passed ? "PASSED" : "FAILED"}`);
  console.log(`  envelope_id = ${staleness.envelope_id}`);
  console.log(`  data_hash = ${envelope.claim.subject.data_hash}`);
  console.log(`  adapter = ${envelope.attestation.adapter_id}`);
}

// Run with real credentials:
// settleMarket("market-001", "user-abc", process.env.WHOOP_ACCESS_TOKEN!);
