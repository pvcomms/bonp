/**
 * JSON Canonicalization Scheme (RFC 8785), the subset BONP needs.
 *
 * BONP-1.0 specified canonicalization as:
 *
 *     JSON.stringify(value, Object.keys(value).sort())
 *
 * The second argument to JSON.stringify is a *replacer*, not a sorter.
 * When it is an array it acts as a key allow-list applied at every
 * nesting depth, so a top-level key list erases every nested object:
 * each one serializes as {}. Every BONP-1.0 envelope therefore
 * canonicalized to the same string, which made envelope_id a constant
 * and — because §3.2 signs over this output — made one signature valid
 * for every claim sharing a top-level shape.
 *
 * See SPEC.md §3.1 and ERRATA.md for the full write-up.
 *
 * This implementation sorts keys by UTF-16 code unit at every level, as
 * RFC 8785 §3.2.3 requires, and rejects the values JSON cannot represent
 * deterministically.
 */

export class CanonicalizationError extends Error {
  /** JSONPath-style location of the offending value, e.g. `$.claim.window.start`. */
  readonly path: string;

  constructor(message: string, path: string) {
    const located = `$${path}`;
    super(`${message} (at ${located})`);
    this.name = "CanonicalizationError";
    this.path = located;
  }
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/**
 * Serialize a value to its RFC 8785 canonical JSON form.
 *
 * `undefined` properties are dropped, matching JSON.stringify. Anything
 * that cannot round-trip deterministically — NaN, Infinity, functions,
 * symbols, bigints, cyclic references — throws rather than silently
 * producing a different string on the verifier's machine.
 */
export function canonicalJSON(value: unknown): string {
  return write(value, "", new Set());
}

function write(value: unknown, path: string, seen: Set<object>): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number":
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError(`non-finite number ${value}`, path);
      }
      // ECMAScript Number::toString is already the shortest round-tripping
      // representation, which is what RFC 8785 §3.2.2.3 requires. The one
      // adjustment: -0 must serialize as 0.
      return Object.is(value, -0) ? "0" : String(value);

    case "string":
      return quote(value);

    case "bigint":
      throw new CanonicalizationError(
        "bigint has no JSON representation",
        path,
      );

    case "undefined":
    case "function":
    case "symbol":
      throw new CanonicalizationError(
        `${typeof value} is not serializable`,
        path,
      );
  }

  const obj = value as object;
  if (seen.has(obj)) {
    throw new CanonicalizationError("circular reference", path);
  }
  seen.add(obj);

  try {
    if (Array.isArray(obj)) {
      const parts = obj.map((item, i) =>
        item === undefined ? "null" : write(item, `${path}[${i}]`, seen),
      );
      return `[${parts.join(",")}]`;
    }

    if (obj instanceof Date) {
      throw new CanonicalizationError(
        "Date is ambiguous; pass an ISO-8601 string instead",
        path,
      );
    }

    const entries = Object.entries(obj as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      // RFC 8785 §3.2.3: sort by UTF-16 code unit, which is what the
      // default comparator on a JS string already does.
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

    const parts = entries.map(
      ([k, v]) => `${quote(k)}:${write(v, `${path}.${k}`, seen)}`,
    );
    return `{${parts.join(",")}}`;
  } finally {
    seen.delete(obj);
  }
}

const ESCAPES: Record<string, string> = {
  "\b": "\\b",
  "\t": "\\t",
  "\n": "\\n",
  "\f": "\\f",
  "\r": "\\r",
  '"': '\\"',
  "\\": "\\\\",
};

function quote(s: string): string {
  let out = '"';
  for (const ch of s) {
    const escape = ESCAPES[ch];
    if (escape !== undefined) {
      out += escape;
      continue;
    }
    const code = ch.codePointAt(0)!;
    // RFC 8785 §3.2.2.2: escape C0 controls, emit everything else literally.
    out += code < 0x20 ? `\\u${code.toString(16).padStart(4, "0")}` : ch;
  }
  return out + '"';
}

export type { Json };
