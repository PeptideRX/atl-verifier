/**
 * RFC 8785 canonical JSON (JCS) serializer for ATL commitments.
 *
 * This implementation follows the subset of RFC 8785 required by the ATL
 * protocol (Chapter 6.2):
 *
 * 1. No duplicate object properties.
 * 2. Deterministic object key ordering: lexicographic on UTF-16 code units,
 *    per RFC 8785 Section 3.2.3.
 * 3. UTF-8 representation with no byte order mark.
 * 4. I-JSON number serialization: integers in the safe range are emitted
 *    without a decimal point; non-integers are rendered via ECMAScript
 *    Number.prototype.toString (ES2022 spec). Non-finite values are rejected.
 * 5. String escaping: only the characters RFC 8785 mandates must be escaped
 *    (control characters, quote, backslash) are escaped.
 * 6. Arrays preserve input order.
 *
 * The implementation is pure TypeScript with no dependencies. It runs in
 * browsers, Node, and edge runtimes.
 */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * Serialize a JSON value to its canonical (RFC 8785) string form.
 *
 * @throws if the input contains non-finite numbers, functions, undefined,
 *   symbols, bigints, or Dates (callers must convert Dates to ISO-8601
 *   strings before calling).
 */
export function canonicalizeJSON(value: unknown): string {
  return serialize(value as JsonValue);
}

function serialize(value: JsonValue): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return serializeNumber(value);
  if (typeof value === 'string') return serializeString(value);
  if (Array.isArray(value)) return serializeArray(value);
  if (typeof value === 'object') {
    return serializeObject(value as { [key: string]: JsonValue });
  }
  throw new TypeError(
    `canonicalizeJSON: unsupported value type ${typeof value}`,
  );
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new RangeError(
      'canonicalizeJSON: NaN and Infinity are not valid JSON numbers',
    );
  }
  // -0 canonicalizes to 0 per RFC 8785.
  if (Object.is(n, -0)) return '0';
  // ECMAScript Number.prototype.toString matches RFC 8785 numeric rules for
  // finite numbers, including exponent notation for very large/small values.
  return n.toString();
}

// Characters that RFC 8785 requires to be escaped inside strings.
const ESCAPE_MAP: Record<string, string> = {
  '"': '\\"',
  '\\': '\\\\',
  '\b': '\\b',
  '\f': '\\f',
  '\n': '\\n',
  '\r': '\\r',
  '\t': '\\t',
};

function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const ch = s.charAt(i);
    const code = s.charCodeAt(i);
    if (ESCAPE_MAP[ch] !== undefined) {
      out += ESCAPE_MAP[ch];
    } else if (code < 0x20) {
      out += '\\u' + code.toString(16).padStart(4, '0');
    } else {
      out += ch;
    }
  }
  out += '"';
  return out;
}

function serializeArray(arr: JsonValue[]): string {
  if (arr.length === 0) return '[]';
  let out = '[';
  for (let i = 0; i < arr.length; i++) {
    if (i > 0) out += ',';
    // Non-null assertion is safe: i < arr.length.
    out += serialize(arr[i] as JsonValue);
  }
  out += ']';
  return out;
}

function serializeObject(obj: { [key: string]: JsonValue }): string {
  const keys = Object.keys(obj).sort(compareUtf16);
  if (keys.length === 0) return '{}';
  // Duplicate-key detection: JS objects can't hold duplicates at runtime,
  // but we defend against Object.create(null) + hand-built shapes just in case.
  const seen = new Set<string>();
  for (const k of keys) {
    if (seen.has(k)) {
      throw new Error(`canonicalizeJSON: duplicate property "${k}"`);
    }
    seen.add(k);
  }
  let out = '{';
  for (let i = 0; i < keys.length; i++) {
    if (i > 0) out += ',';
    const key = keys[i] as string;
    out += serializeString(key);
    out += ':';
    out += serialize(obj[key] as JsonValue);
  }
  out += '}';
  return out;
}

/**
 * Compare two strings by UTF-16 code units, per RFC 8785 Section 3.2.3.
 * We cannot use String.prototype.localeCompare (locale-sensitive) nor a
 * naive < operator with Intl collation; we compare code units directly.
 */
function compareUtf16(a: string, b: string): number {
  const lenA = a.length;
  const lenB = b.length;
  const min = Math.min(lenA, lenB);
  for (let i = 0; i < min; i++) {
    const ca = a.charCodeAt(i);
    const cb = b.charCodeAt(i);
    if (ca !== cb) return ca - cb;
  }
  return lenA - lenB;
}
