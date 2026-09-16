// BONP live oracle feed — synthetic SSE stream.
// Emits one reading per source on a staggered cadence with ed25519-style
// signature verification result (simulated), latency, and confidence.
// Closes itself after ~90s so serverless execution stays bounded; the client
// auto-reconnects.

import { createHash, randomBytes } from "crypto";

const SOURCES = [
  { name: "whoop", baseline: 48, noise: 6, cadenceMs: 1500, confidence: 0.95 },
  { name: "oura", baseline: 51, noise: 5, cadenceMs: 2100, confidence: 0.92 },
  {
    name: "apple_health",
    baseline: 46,
    noise: 8,
    cadenceMs: 2800,
    confidence: 0.78,
  },
];

const MAX_DURATION_MS = 90_000;
const SIG_FAIL_RATE = 0.02;

function nextReading(src, tick) {
  const drift = Math.sin(tick / 8) * 4;
  const jitter = (Math.random() - 0.5) * src.noise;
  const value = Math.max(0, Math.min(100, src.baseline + drift + jitter));
  return Number(value.toFixed(2));
}

function simulateSignatureCheck() {
  const start = Date.now();
  const payload = randomBytes(64);
  createHash("sha256").update(payload).digest();
  const latency_ms = Date.now() - start + Math.floor(Math.random() * 40) + 12;
  const signature_ok = Math.random() > SIG_FAIL_RATE;
  return { latency_ms, signature_ok };
}

export default function handler(req, res) {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.flushHeaders?.();

  res.write(`retry: 2000\n\n`);
  res.write(`: bonp-live connected ${new Date().toISOString()}\n\n`);

  const timers = [];
  const ticks = Object.fromEntries(SOURCES.map((s) => [s.name, 0]));
  const started = Date.now();
  let closed = false;

  function send(source) {
    if (closed) return;
    const tick = ++ticks[source.name];
    const value = nextReading(source, tick);
    const { latency_ms, signature_ok } = simulateSignatureCheck();
    const payload = {
      t: Date.now(),
      source: source.name,
      value,
      confidence: source.confidence,
      signature_ok,
      latency_ms,
      tick,
    };
    try {
      res.write(`event: reading\n`);
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    } catch {
      cleanup();
    }
  }

  SOURCES.forEach((s) => {
    const offset = Math.floor(Math.random() * s.cadenceMs);
    timers.push(setTimeout(() => send(s), offset));
    timers.push(setInterval(() => send(s), s.cadenceMs));
  });

  const heartbeat = setInterval(() => {
    if (closed) return;
    try {
      res.write(`: hb ${Date.now()}\n\n`);
    } catch {
      cleanup();
    }
  }, 15_000);
  timers.push(heartbeat);

  const hardStop = setTimeout(() => {
    try {
      res.write(`event: close\ndata: {"reason":"max_duration"}\n\n`);
    } catch {}
    cleanup();
  }, MAX_DURATION_MS);
  timers.push(hardStop);

  function cleanup() {
    if (closed) return;
    closed = true;
    timers.forEach((t) => {
      try {
        clearTimeout(t);
        clearInterval(t);
      } catch {}
    });
    try {
      res.end();
    } catch {}
  }

  req.on("close", cleanup);
  req.on("aborted", cleanup);
}

export const config = {
  runtime: "nodejs",
  maxDuration: 120,
};
