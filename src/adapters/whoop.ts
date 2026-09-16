import { createHash } from "crypto";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import type {
  BiometricEnvelope,
  BiometricMetric,
  BiometricClaim,
} from "../types.js";
import type {
  BiometricAdapter,
  AdapterCapabilities,
  DateRange,
  FetchOptions,
} from "../adapter.js";
import { createEnvelope, generateNonce } from "../envelope.js";

// @noble/ed25519 v2 requires sha512 to be wired in
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const ADAPTER_ID = "bonp-whoop-v1";
const ADAPTER_VERSION = "1.0.0";
const WHOOP_BASE = "https://api.prod.whoop.com/developer";

// Deterministic seed for v1 adapter keypair — replace with KMS-backed key in production
const ADAPTER_SEED = createHash("sha256")
  .update("bonp-whoop-v1-signing-key")
  .digest();

function isoDate(d: Date): string {
  return d.toISOString().split("T")[0];
}

function hashId(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

async function sign(message: string): Promise<string> {
  const msgBytes = Buffer.from(message, "utf8");
  const sig = await ed.signAsync(msgBytes, ADAPTER_SEED);
  return Buffer.from(sig).toString("hex");
}

function getPublicKey(): string {
  const pub = ed.getPublicKey(ADAPTER_SEED);
  return Buffer.from(pub).toString("hex");
}

async function buildEnvelope(
  userId: string,
  metric: BiometricMetric,
  value: number,
  unit: string,
  timestamp: string,
  window: { start: string; end: string },
  rawJson: object,
  deviceModel?: string,
): Promise<BiometricEnvelope> {
  const dataHash = createHash("sha256")
    .update(JSON.stringify(rawJson))
    .digest("hex");

  const nonce = generateNonce();
  const fetchTimestamp = new Date().toISOString();

  const claim: BiometricClaim = {
    metric,
    value,
    unit,
    timestamp,
    window,
    device: {
      provider: "whoop",
      device_id: hashId(`whoop-device-${userId}`),
      model: deviceModel,
    },
    subject: {
      id: hashId(userId),
      data_hash: dataHash,
    },
  };

  const canonicalClaim = JSON.stringify(claim);
  const signature = await sign(canonicalClaim);

  return createEnvelope(
    claim,
    {
      provider_signature: signature,
      provider_public_key: getPublicKey(),
      adapter_id: ADAPTER_ID,
      adapter_version: ADAPTER_VERSION,
      fetch_timestamp: fetchTimestamp,
      nonce,
    },
    {
      staleness_window_ms: 12 * 60 * 60 * 1000, // 12h
      confidence_score: 0.95,
      dispute_window_ms: 24 * 60 * 60 * 1000, // 24h
    },
  );
}

type WhoopRecoveryRecord = {
  created_at: string;
  score: {
    recovery_score: number;
    hrv_rmssd_milli: number;
    resting_heart_rate: number;
    spo2_percentage: number;
  };
  cycle_id: number;
};

type WhoopSleepRecord = {
  start: string;
  end: string;
  score: {
    sleep_performance_percentage: number;
    total_in_bed_time_milli: number;
    respiratory_rate: number;
  };
};

type WhoopCycleRecord = {
  start: string;
  score: {
    strain: number;
    average_heart_rate: number;
    kilojoule: number;
  };
};

async function fetchWhoop<T>(
  endpoint: string,
  params: Record<string, string>,
  accessToken: string,
): Promise<T> {
  const url = new URL(`${WHOOP_BASE}${endpoint}`);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));

  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });

  if (res.status === 401) {
    throw Object.assign(new Error("Whoop authentication failed"), {
      code: "BONP-005",
    });
  }

  if (!res.ok) {
    throw new Error(`Whoop API error ${res.status}: ${await res.text()}`);
  }

  return res.json() as Promise<T>;
}

export class WhoopAdapter implements BiometricAdapter {
  readonly id = ADAPTER_ID;
  readonly version = ADAPTER_VERSION;
  readonly provider = "whoop" as const;

  getCapabilities(): AdapterCapabilities {
    return {
      metrics: [
        "recovery_score",
        "hrv_rmssd",
        "resting_heart_rate",
        "sleep_performance",
        "sleep_hours",
        "strain",
        "active_calories",
        "spo2",
        "respiratory_rate",
      ],
      max_lookback_days: 365,
      supports_real_time: false,
      signature_scheme: "adapter_ed25519",
    };
  }

  getPublicKey(): string {
    return getPublicKey();
  }

  async fetchMetric(
    userId: string,
    metric: BiometricMetric,
    range: DateRange,
    options?: FetchOptions,
  ): Promise<BiometricEnvelope> {
    if (!options?.access_token) {
      throw Object.assign(new Error("access_token required for Whoop"), {
        code: "BONP-005",
      });
    }

    const token = options.access_token;
    const startStr = range.start.toISOString();
    const endStr = range.end.toISOString();
    const window = { start: startStr, end: endStr };

    const recoveryMetrics: BiometricMetric[] = [
      "recovery_score",
      "hrv_rmssd",
      "resting_heart_rate",
      "spo2",
    ];
    const sleepMetrics: BiometricMetric[] = [
      "sleep_performance",
      "sleep_hours",
      "respiratory_rate",
    ];
    const cycleMetrics: BiometricMetric[] = ["strain", "active_calories"];

    if (recoveryMetrics.includes(metric)) {
      const data = await fetchWhoop<{ records: WhoopRecoveryRecord[] }>(
        "/v1/recovery",
        { start: startStr, end: endStr, limit: "10" },
        token,
      );

      const record = data.records?.[0];
      if (!record) throw new Error("No recovery data in range");

      const metricMap: Record<string, [number, string]> = {
        recovery_score: [record.score.recovery_score, "percent"],
        hrv_rmssd: [record.score.hrv_rmssd_milli, "ms"],
        resting_heart_rate: [record.score.resting_heart_rate, "bpm"],
        spo2: [record.score.spo2_percentage, "percent"],
      };

      const [value, unit] = metricMap[metric];
      return buildEnvelope(
        userId,
        metric,
        value,
        unit,
        record.created_at,
        window,
        record,
      );
    }

    if (sleepMetrics.includes(metric)) {
      const data = await fetchWhoop<{ records: WhoopSleepRecord[] }>(
        "/v1/sleep",
        { start: startStr, end: endStr, limit: "10" },
        token,
      );

      const record = data.records?.[0];
      if (!record) throw new Error("No sleep data in range");

      const sleepHours = record.score.total_in_bed_time_milli / 3_600_000;

      const metricMap: Record<string, [number, string]> = {
        sleep_performance: [
          record.score.sleep_performance_percentage,
          "percent",
        ],
        sleep_hours: [sleepHours, "hours"],
        respiratory_rate: [record.score.respiratory_rate, "breaths/min"],
      };

      const [value, unit] = metricMap[metric];
      return buildEnvelope(
        userId,
        metric,
        value,
        unit,
        record.start,
        window,
        record,
      );
    }

    if (cycleMetrics.includes(metric)) {
      const data = await fetchWhoop<{ records: WhoopCycleRecord[] }>(
        "/v1/cycle",
        { start: startStr, end: endStr, limit: "10" },
        token,
      );

      const record = data.records?.[0];
      if (!record) throw new Error("No cycle data in range");

      // Whoop kilojoules → active calories (1 kJ ≈ 0.239 kcal)
      const activeCalories = record.score.kilojoule * 0.239006;

      const metricMap: Record<string, [number, string]> = {
        strain: [record.score.strain, "au"],
        active_calories: [activeCalories, "kcal"],
      };

      const [value, unit] = metricMap[metric];
      return buildEnvelope(
        userId,
        metric,
        value,
        unit,
        record.start,
        window,
        record,
      );
    }

    throw Object.assign(
      new Error(`Metric "${metric}" not supported by WhoopAdapter`),
      { code: "BONP-006" },
    );
  }

  async verifySignature(envelope: BiometricEnvelope): Promise<boolean> {
    if (
      envelope.attestation.adapter_id !== ADAPTER_ID ||
      envelope.attestation.provider_public_key !== getPublicKey()
    ) {
      return false;
    }

    try {
      const canonicalClaim = JSON.stringify(envelope.claim);
      const sigBytes = Buffer.from(
        envelope.attestation.provider_signature,
        "hex",
      );
      const pubBytes = Buffer.from(
        envelope.attestation.provider_public_key,
        "hex",
      );
      const msgBytes = Buffer.from(canonicalClaim, "utf8");
      return await ed.verifyAsync(sigBytes, msgBytes, pubBytes);
    } catch {
      return false;
    }
  }
}
