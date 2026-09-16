export { canonicalJSON, CanonicalizationError } from "./canonical.js";
export { signClaim, verifyClaim, signingMessage, publicKeyFor, generatePrivateKey } from "./signature.js";
// Core types
export type {
  BiometricProvider,
  BiometricMetric,
  BiometricWindow,
  BiometricClaim,
  BiometricAttestation,
  SettlementMetadata,
  BiometricEnvelope,
  DisputeRecord,
  DisputeStatus,
  StalenessProof,
  BONPError,
} from "./types.js";

// Envelope module
export {
  createEnvelope,
  canonicalize,
  envelopeId,
  generateNonce,
  verifyEnvelope,
  _resetNonceRegistry,
} from "./envelope.js";

// Adapter interface + registry
export type {
  AdapterCapabilities,
  DateRange,
  FetchOptions,
  BiometricAdapter,
} from "./adapter.js";
export { AdapterRegistry } from "./adapter.js";

// Dispute module
export {
  openDispute,
  submitEvidence,
  resolveDispute,
  isDisputeExpired,
  adjudicate,
} from "./dispute.js";

// Staleness module
export {
  generateStalenessProof,
  checkFreshness,
  freshestValidEnvelope,
} from "./staleness.js";

// Reference adapters
export { WhoopAdapter } from "./adapters/whoop.js";
export { OuraAdapter } from "./adapters/oura.js";
export {
  AppleHealthAdapter,
  fromHealthKitExport,
  parseHealthKitXml,
} from "./adapters/apple-health.js";
export type { HealthKitReading } from "./adapters/apple-health.js";
