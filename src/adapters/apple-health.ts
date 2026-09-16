import { createHash } from "crypto";
import { readFileSync } from "fs";
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

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const ADAPTER_ID = "bonp-apple-health-v1";
const ADAPTER_VERSION = "1.0.0";

const ADAPTER_SEED = createHash("sha256")
  .update("bonp-apple-health-v1-signing-key")
  .digest();

function hashId(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

async function sign(message: string): Promise<string> {
  const msgBytes = Buffer.from(message, "utf8");
  const sig = await ed.signAsync(msgBytes, ADAPTER_SEED);
  return Buffer.from(sig).toString("hex");
}

function getPublicKey(): string {
  return Buffer.from(ed.getPublicKey(ADAPTER_SEED)).toString("hex");
}

export interface HealthKitReading {
  type: string; // e.g. "HKQuantityTypeIdentifierStepCount"
  value: number;
  unit: string;
  startDate: string;
  endDate: string;
  sourceName?: string;
  sourceVersion?: string;
  device?: string;
}

// Mapping from HKQuantityTypeIdentifier → BONP metric
const HK_TYPE_MAP: Record<string, BiometricMetric> = {
  HKQuantityTypeIdentifierStepCount: "step_count",
  HKQuantityTypeIdentifierRestingHeartRate: "resting_heart_rate",
  HKQuantityTypeIdentifierOxygenSaturation: "spo2",
  HKQuantityTypeIdentifierSleepAnalysis: "sleep_hours",
  HKCategoryTypeIdentifierSleepAnalysis: "sleep_hours",
};

const METRIC_TO_HK: Record<BiometricMetric, string[]> = {
  step_count: ["HKQuantityTypeIdentifierStepCount"],
  resting_heart_rate: ["HKQuantityTypeIdentifierRestingHeartRate"],
  spo2: ["HKQuantityTypeIdentifierOxygenSaturation"],
  sleep_hours: [
    "HKQuantityTypeIdentifierSleepAnalysis",
    "HKCategoryTypeIdentifierSleepAnalysis",
  ],
  // Not natively in Apple Health export in simple form
  recovery_score: [],
  hrv_rmssd: ["HKQuantityTypeIdentifierHeartRateVariabilitySDNN"],
  sleep_performance: [],
  strain: [],
  readiness_score: [],
  respiratory_rate: ["HKQuantityTypeIdentifierRespiratoryRate"],
  active_calories: ["HKQuantityTypeIdentifierActiveEnergyBurned"],
};

async function buildEnvelope(
  userId: string,
  metric: BiometricMetric,
  value: number,
  unit: string,
  timestamp: string,
  window: { start: string; end: string },
  rawData: object,
): Promise<BiometricEnvelope> {
  const dataHash = createHash("sha256")
    .update(JSON.stringify(rawData))
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
      provider: "apple_health",
      device_id: hashId(`apple-health-device-${userId}`),
      model: "iPhone/Apple Watch",
    },
    subject: {
      id: hashId(userId),
      data_hash: dataHash,
    },
  };

  const signature = await sign(JSON.stringify(claim));

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
      staleness_window_ms: 48 * 60 * 60 * 1000, // 48h — exports lag
      confidence_score: 0.88,
      dispute_window_ms: 24 * 60 * 60 * 1000,
    },
  );
}

/**
 * Parse Apple Health XML export into HealthKit readings.
 * Handles the standard export.xml format produced by the Health app.
 */
export function parseHealthKitXml(xml: string): HealthKitReading[] {
  const readings: HealthKitReading[] = [];

  // Simple regex-based parser — no DOM dependency for Node.js compatibility
  const recordRegex = /<Record([^>]+)\/>/g;
  let match: RegExpExecArray | null;

  while ((match = recordRegex.exec(xml)) !== null) {
    const attrs = match[1];
    const get = (name: string): string => {
      const m = new RegExp(`${name}="([^"]*)"`, "i").exec(attrs);
      return m ? m[1] : "";
    };

    const type = get("type");
    const value = parseFloat(get("value")) || 0;
    const unit = get("unit");
    const startDate = get("startDate");
    const endDate = get("endDate");
    const sourceName = get("sourceName");

    if (type && startDate) {
      readings.push({ type, value, unit, startDate, endDate, sourceName });
    }
  }

  return readings;
}

/**
 * Helper: load and parse an Apple Health XML export from disk.
 */
export function fromHealthKitExport(xmlPath: string): HealthKitReading[] {
  const xml = readFileSync(xmlPath, "utf8");
  return parseHealthKitXml(xml);
}

function aggregateReadings(
  readings: HealthKitReading[],
  metric: BiometricMetric,
  range: DateRange,
): { value: number; unit: string; timestamp: string } | null {
  const hkTypes = METRIC_TO_HK[metric];
  if (!hkTypes || hkTypes.length === 0) return null;

  const rangeStart = range.start.getTime();
  const rangeEnd = range.end.getTime();

  const relevant = readings.filter((r) => {
    const ts = new Date(r.startDate).getTime();
    return hkTypes.includes(r.type) && ts >= rangeStart && ts <= rangeEnd;
  });

  if (relevant.length === 0) return null;

  if (metric === "step_count" || metric === "active_calories") {
    // Sum over the window
    const total = relevant.reduce((sum, r) => sum + r.value, 0);
    const unit = metric === "step_count" ? "steps" : "kcal";
    return { value: total, unit, timestamp: relevant[0].startDate };
  }

  if (metric === "sleep_hours") {
    // Sum sleep duration (readings are in hours if unit is "hr", else seconds)
    let totalHours = 0;
    for (const r of relevant) {
      const durationMs =
        new Date(r.endDate).getTime() - new Date(r.startDate).getTime();
      totalHours += durationMs / 3_600_000;
    }
    return {
      value: totalHours,
      unit: "hours",
      timestamp: relevant[0].startDate,
    };
  }

  // For point-in-time metrics, take the most recent reading
  const latest = relevant.sort(
    (a, b) => new Date(b.startDate).getTime() - new Date(a.startDate).getTime(),
  )[0];

  const unitMap: Partial<Record<BiometricMetric, string>> = {
    resting_heart_rate: "bpm",
    spo2: "percent",
    hrv_rmssd: "ms",
    respiratory_rate: "breaths/min",
  };

  return {
    value: latest.value,
    unit: unitMap[metric] ?? latest.unit,
    timestamp: latest.startDate,
  };
}

export class AppleHealthAdapter implements BiometricAdapter {
  readonly id = ADAPTER_ID;
  readonly version = ADAPTER_VERSION;
  readonly provider = "apple_health" as const;

  private readings: HealthKitReading[] = [];

  /**
   * Load readings from a HealthKit export XML file or pre-parsed array.
   * Call before fetchMetric when using the export path.
   */
  loadExport(xmlPathOrReadings: string | HealthKitReading[]): this {
    if (typeof xmlPathOrReadings === "string") {
      this.readings = fromHealthKitExport(xmlPathOrReadings);
    } else {
      this.readings = xmlPathOrReadings;
    }
    return this;
  }

  getCapabilities(): AdapterCapabilities {
    return {
      metrics: [
        "step_count",
        "resting_heart_rate",
        "spo2",
        "sleep_hours",
        "hrv_rmssd",
        "respiratory_rate",
        "active_calories",
      ],
      max_lookback_days: 3650, // exports can span years
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
    // If readings haven't been loaded via loadExport(), attempt to read
    // from options.access_token treated as a file path (iOS bridge mode)
    let readings = this.readings;
    if (readings.length === 0 && options?.access_token) {
      readings = fromHealthKitExport(options.access_token);
    }

    if (readings.length === 0) {
      throw new Error(
        "No HealthKit data loaded. Call loadExport() or pass xmlPath as access_token.",
      );
    }

    const result = aggregateReadings(readings, metric, range);
    if (!result) {
      throw Object.assign(
        new Error(`Metric "${metric}" not found in HealthKit data for range`),
        { code: "BONP-006" },
      );
    }

    const window = {
      start: range.start.toISOString(),
      end: range.end.toISOString(),
    };

    return buildEnvelope(
      userId,
      metric,
      result.value,
      result.unit,
      result.timestamp,
      window,
      { readings: readings.slice(0, 10) }, // include sample for data_hash
    );
  }

  async verifySignature(envelope: BiometricEnvelope): Promise<boolean> {
    if (envelope.attestation.adapter_id !== ADAPTER_ID) return false;

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
