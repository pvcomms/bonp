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

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const ADAPTER_ID = "bonp-oura-v1";
const ADAPTER_VERSION = "1.0.0";
const OURA_BASE = "https://api.ouraring.com";

const ADAPTER_SEED = createHash("sha256")
  .update("bonp-oura-v1-signing-key")
  .digest();

function hashId(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

function isoDate(d: Date): string {
  return d.toISOString().split("T")[0];
}

async function sign(message: string): Promise<string> {
  const msgBytes = Buffer.from(message, "utf8");
  const sig = await ed.signAsync(msgBytes, ADAPTER_SEED);
  return Buffer.from(sig).toString("hex");
}

function getPublicKey(): string {
  return Buffer.from(ed.getPublicKey(ADAPTER_SEED)).toString("hex");
}

async function buildEnvelope(
  userId: string,
  metric: BiometricMetric,
  value: number,
  unit: string,
  timestamp: string,
  window: { start: string; end: string },
  rawJson: object,
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
      provider: "oura",
      device_id: hashId(`oura-device-${userId}`),
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
      staleness_window_ms: 24 * 60 * 60 * 1000, // 24h (Oura syncs daily)
      confidence_score: 0.93,
      dispute_window_ms: 24 * 60 * 60 * 1000,
    },
  );
}

async function fetchOura<T>(
  endpoint: string,
  params: Record<string, string>,
  accessToken: string,
): Promise<T> {
  const url = new URL(`${OURA_BASE}${endpoint}`);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));

  const res = await fetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (res.status === 401) {
    throw Object.assign(new Error("Oura authentication failed"), {
      code: "BONP-005",
    });
  }

  if (!res.ok) {
    throw new Error(`Oura API error ${res.status}: ${await res.text()}`);
  }

  return res.json() as Promise<T>;
}

type OuraReadinessRecord = {
  day: string;
  score: number;
  temperature_deviation?: number;
};

type OuraSleepRecord = {
  day: string;
  bedtime_start: string;
  bedtime_end: string;
  total_sleep_duration: number; // seconds
  efficiency: number; // 0-100
};

type OuraActivityRecord = {
  day: string;
  steps: number;
  active_calories: number;
};

export class OuraAdapter implements BiometricAdapter {
  readonly id = ADAPTER_ID;
  readonly version = ADAPTER_VERSION;
  readonly provider = "oura" as const;

  getCapabilities(): AdapterCapabilities {
    return {
      metrics: [
        "readiness_score",
        "sleep_hours",
        "sleep_performance",
        "step_count",
        "active_calories",
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
      throw Object.assign(new Error("access_token required for Oura"), {
        code: "BONP-005",
      });
    }

    const token = options.access_token;
    const startDate = isoDate(range.start);
    const endDate = isoDate(range.end);
    const window = {
      start: range.start.toISOString(),
      end: range.end.toISOString(),
    };

    if (metric === "readiness_score") {
      const data = await fetchOura<{ data: OuraReadinessRecord[] }>(
        "/v2/usercollection/daily_readiness",
        { start_date: startDate, end_date: endDate },
        token,
      );

      const record = data.data?.[0];
      if (!record) throw new Error("No readiness data in range");

      return buildEnvelope(
        userId,
        metric,
        record.score,
        "score",
        `${record.day}T00:00:00.000Z`,
        window,
        record,
      );
    }

    if (metric === "sleep_hours" || metric === "sleep_performance") {
      const data = await fetchOura<{ data: OuraSleepRecord[] }>(
        "/v2/usercollection/sleep",
        { start_date: startDate, end_date: endDate },
        token,
      );

      const record = data.data?.[0];
      if (!record) throw new Error("No sleep data in range");

      const value =
        metric === "sleep_hours"
          ? record.total_sleep_duration / 3600
          : record.efficiency;

      const unit = metric === "sleep_hours" ? "hours" : "percent";

      return buildEnvelope(
        userId,
        metric,
        value,
        unit,
        record.bedtime_start,
        window,
        record,
      );
    }

    if (metric === "step_count" || metric === "active_calories") {
      const data = await fetchOura<{ data: OuraActivityRecord[] }>(
        "/v2/usercollection/daily_activity",
        { start_date: startDate, end_date: endDate },
        token,
      );

      const record = data.data?.[0];
      if (!record) throw new Error("No activity data in range");

      const value =
        metric === "step_count" ? record.steps : record.active_calories;
      const unit = metric === "step_count" ? "steps" : "kcal";

      return buildEnvelope(
        userId,
        metric,
        value,
        unit,
        `${record.day}T00:00:00.000Z`,
        window,
        record,
      );
    }

    throw Object.assign(
      new Error(`Metric "${metric}" not supported by OuraAdapter`),
      { code: "BONP-006" },
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
