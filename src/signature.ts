/**
 * Ed25519 signing and verification over the canonical claim.
 *
 * BONP-1.0's verifyEnvelope only checked that provider_signature was a
 * non-empty string. Combined with the canonicalization defect in
 * canonical.ts, that meant any 1-character signature validated any
 * claim. Verification now actually runs the curve.
 */

import { ed25519 } from "@noble/curves/ed25519";
import type { BiometricClaim } from "./types.js";
import { canonicalJSON } from "./canonical.js";

const ENCODER = new TextEncoder();

function fromHex(
  hex: string,
  label: string,
  expectedBytes: number,
): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length !== expectedBytes * 2) {
    throw new Error(
      `${label} must be ${expectedBytes * 2} hex characters, got ${hex.length}`,
    );
  }
  const out = new Uint8Array(expectedBytes);
  for (let i = 0; i < expectedBytes; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The exact bytes a signature covers: canonical JSON of the claim, UTF-8. */
export function signingMessage(claim: BiometricClaim): Uint8Array {
  return ENCODER.encode(canonicalJSON(claim));
}

export function signClaim(
  claim: BiometricClaim,
  privateKeyHex: string,
): string {
  const key = fromHex(privateKeyHex, "private key", 32);
  return toHex(ed25519.sign(signingMessage(claim), key));
}

/**
 * Verify a claim signature.
 *
 * Returns false for a bad signature and for malformed key or signature
 * material. It does not throw on attacker-controlled input: a verifier
 * that throws on a malformed public key is a denial-of-service surface,
 * since the key arrives inside the envelope being checked.
 */
export function verifyClaim(
  claim: BiometricClaim,
  signatureHex: string,
  publicKeyHex: string,
): boolean {
  try {
    return ed25519.verify(
      fromHex(signatureHex, "signature", 64),
      signingMessage(claim),
      fromHex(publicKeyHex, "public key", 32),
    );
  } catch {
    return false;
  }
}

export function publicKeyFor(privateKeyHex: string): string {
  return toHex(ed25519.getPublicKey(fromHex(privateKeyHex, "private key", 32)));
}

export function generatePrivateKey(): string {
  return toHex(ed25519.utils.randomPrivateKey());
}
