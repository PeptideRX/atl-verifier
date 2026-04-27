/**
 * Python-compatible canonical JSON (JCS dialect) for the Peptide Design
 * Attestation (PDA) protocol.
 *
 * The PDA's Rust reference and the Python reference agree on a single
 * canonical JSON dialect that is almost RFC 8785 but differs in one
 * load-bearing way: Python's `json.dumps` serializes a float that happens
 * to equal a whole number (for example `-9.0`) as the literal string
 * `-9.0`, not the strict RFC 8785 `-9`. The Python reference is the
 * oracle, so this TypeScript encoder matches Python byte-for-byte on
 * every number in the V1 schema, including `-9.0`, `0.6`, `-7.5`, and
 * `-6.0`.
 *
 * JavaScript's native `JSON.parse` loses the int/float distinction at
 * parse time: a literal `-9.0` in the wire bytes becomes the Number
 * `-9`, and a literal `-9` becomes the same Number `-9`. Feeding that
 * back through `JSON.stringify` (or any naive canonicalizer) emits
 * `-9`, which diverges from Python.
 *
 * To preserve the Python dialect we ship two tools:
 *
 *   1. {@link parsePythonJSON}, a small JSON parser that preserves the
 *      original numeric literal string for any token containing a `.`
 *      or an exponent marker. Float-literal numbers are wrapped in a
 *      {@link PyFloatNumber} tagged-value object so downstream code can
 *      distinguish them from plain integers.
 *   2. {@link canonicalizePythonJSON}, which walks a tree of
 *      `JsonValue | PyFloatNumber` and emits the byte-identical Python
 *      dialect: sorted object keys, no whitespace, backslash escapes
 *      for control characters, UTF-8 passthrough for non-ASCII, and the
 *      preserved literal string for every float token.
 *
 * The encoder also accepts "native" JSON trees (produced by
 * `JSON.parse`) as a convenience. Numbers without a wrapper are emitted
 * via `Number.prototype.toString`, which matches Python's output for
 * integers and for non-whole-number floats but diverges on whole-number
 * floats. Callers who need byte-identical parity on `-9.0`-style inputs
 * MUST use {@link parsePythonJSON} rather than `JSON.parse`.
 *
 * Scope: research use only, nonclinical.
 */
/**
 * Type guard for {@link PyFloatNumber}.
 */
export function isPyFloatNumber(v) {
    return (typeof v === 'object' &&
        v !== null &&
        v.__jcsFloat === true &&
        typeof v.literal === 'string');
}
/**
 * Wrap a JavaScript number as a Python-style float literal.
 *
 * The literal is derived from the number via `Number.prototype.toString`
 * with special handling for the whole-number case: `-9` becomes the
 * literal `-9.0`, `0` becomes `0.0`, and so on. Callers who need to
 * pin the exact literal (for example to match `0.65` vs `0.650`) should
 * construct the wrapper by hand: `{ __jcsFloat: true, literal: '0.650' }`.
 */
export function asPythonFloat(n) {
    if (!Number.isFinite(n)) {
        throw new RangeError('asPythonFloat: value must be finite');
    }
    const js = n === 0 ? (Object.is(n, -0) ? '-0' : '0') : n.toString();
    const literal = js.includes('.') || js.includes('e') || js.includes('E') ? js : `${js}.0`;
    return { __jcsFloat: true, literal };
}
/**
 * Parse a Python-dialect JSON string into a `JsonValue | PyFloatNumber`
 * tree. Numeric literals containing a `.` or an exponent marker are
 * wrapped in a {@link PyFloatNumber}; integers (no `.`, no exponent)
 * are returned as plain JavaScript numbers.
 *
 * The parser follows RFC 8259 for the token grammar and rejects
 * non-finite numbers, duplicate object keys, and leading zeros
 * per RFC 8259 Section 6. Strings are decoded with full `\uXXXX` +
 * surrogate-pair support.
 *
 * @throws SyntaxError with a byte offset on any malformed input.
 */
export function parsePythonJSON(src) {
    const p = new Parser(src);
    p.skipWhitespace();
    const v = p.parseValue();
    p.skipWhitespace();
    if (p.i !== src.length) {
        throw new SyntaxError(`parsePythonJSON: trailing garbage at offset ${p.i}`);
    }
    return v;
}
/**
 * Serialize a `JsonValue | PyFloatNumber` tree to Python-compatible
 * canonical JSON (JCS dialect). Returns a UTF-8 string.
 *
 * Rules:
 *
 *   - Object keys sorted lexicographically by UTF-8 byte order.
 *     Equivalent to Python's `sort_keys=True` for ASCII keys, which is
 *     all the V1 schema uses.
 *   - No whitespace between tokens, no trailing newline.
 *   - Strings: escape `"`, `\\`, `\b` (U+0008), `\t`, `\n`, `\f`, `\r`;
 *     escape all other U+0000 to U+001F as `\uXXXX`; pass all other
 *     characters through as UTF-8. Matches Python's default escaping
 *     with `ensure_ascii=False`.
 *   - Numbers: integers emitted without a decimal point; floats
 *     (wrapped in {@link PyFloatNumber}) emitted via the preserved
 *     literal string; plain JS numbers that happen to be non-integer
 *     emitted via `Number.prototype.toString`.
 *   - `null`, `true`, `false` emit as-is.
 *
 * Rejects NaN, Infinity, and -Infinity at the number level.
 */
export function canonicalizePythonJSON(value) {
    return emit(value);
}
function emit(v) {
    if (v === null)
        return 'null';
    if (v === true)
        return 'true';
    if (v === false)
        return 'false';
    if (isPyFloatNumber(v))
        return v.literal;
    if (typeof v === 'number')
        return emitNumber(v);
    if (typeof v === 'string')
        return emitString(v);
    if (Array.isArray(v))
        return emitArray(v);
    if (typeof v === 'object') {
        return emitObject(v);
    }
    throw new TypeError(`canonicalizePythonJSON: unsupported value type ${typeof v}`);
}
function emitNumber(n) {
    if (!Number.isFinite(n)) {
        throw new RangeError('canonicalizePythonJSON: NaN and Infinity are not valid JSON');
    }
    if (Object.is(n, -0))
        return '0';
    return n.toString();
}
const SHORT_ESCAPES = {
    0x08: '\\b',
    0x09: '\\t',
    0x0a: '\\n',
    0x0c: '\\f',
    0x0d: '\\r',
    0x22: '\\"',
    0x5c: '\\\\',
};
function emitString(s) {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
        const code = s.charCodeAt(i);
        const short = SHORT_ESCAPES[code];
        if (short !== undefined) {
            out += short;
        }
        else if (code < 0x20) {
            out += '\\u' + code.toString(16).padStart(4, '0');
        }
        else {
            out += s.charAt(i);
        }
    }
    out += '"';
    return out;
}
function emitArray(arr) {
    if (arr.length === 0)
        return '[]';
    let out = '[';
    for (let i = 0; i < arr.length; i++) {
        if (i > 0)
            out += ',';
        out += emit(arr[i]);
    }
    out += ']';
    return out;
}
function emitObject(obj) {
    const keys = Object.keys(obj).sort(compareUtf8);
    if (keys.length === 0)
        return '{}';
    let out = '{';
    for (let i = 0; i < keys.length; i++) {
        if (i > 0)
            out += ',';
        const key = keys[i];
        out += emitString(key);
        out += ':';
        out += emit(obj[key]);
    }
    out += '}';
    return out;
}
/**
 * Compare two UTF-8-encoded strings by byte order. This matches the Rust
 * reference's `sort_unstable` over string slices, which in turn matches
 * Python's `sort_keys=True` for every key the V1 schema uses (all of
 * which are ASCII). A future non-ASCII key would need to be audited
 * against the Python reference to confirm the two implementations agree
 * on byte ordering versus code-point ordering.
 */
function compareUtf8(a, b) {
    // For ASCII keys, UTF-16 code-unit order equals UTF-8 byte order.
    // Encode explicitly when either string contains non-ASCII so we match
    // Python's behavior under sort_keys=True (which sorts by codepoint).
    let asciiOnly = true;
    for (let i = 0; i < a.length; i++) {
        if (a.charCodeAt(i) > 0x7f) {
            asciiOnly = false;
            break;
        }
    }
    if (asciiOnly) {
        for (let i = 0; i < b.length; i++) {
            if (b.charCodeAt(i) > 0x7f) {
                asciiOnly = false;
                break;
            }
        }
    }
    if (asciiOnly) {
        if (a < b)
            return -1;
        if (a > b)
            return 1;
        return 0;
    }
    const enc = new TextEncoder();
    const ab = enc.encode(a);
    const bb = enc.encode(b);
    const n = Math.min(ab.length, bb.length);
    for (let i = 0; i < n; i++) {
        const da = ab[i];
        const db = bb[i];
        if (da !== db)
            return da - db;
    }
    return ab.length - bb.length;
}
// ---------------------------------------------------------------------------
// Minimal JSON parser that preserves float-literal strings.
// ---------------------------------------------------------------------------
class Parser {
    src;
    i = 0;
    constructor(src) {
        this.src = src;
    }
    skipWhitespace() {
        while (this.i < this.src.length) {
            const c = this.src.charCodeAt(this.i);
            if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
                this.i++;
            }
            else {
                break;
            }
        }
    }
    parseValue() {
        this.skipWhitespace();
        if (this.i >= this.src.length) {
            throw new SyntaxError('parsePythonJSON: unexpected end of input');
        }
        const c = this.src.charAt(this.i);
        switch (c) {
            case '{':
                return this.parseObject();
            case '[':
                return this.parseArray();
            case '"':
                return this.parseString();
            case 't':
            case 'f':
                return this.parseBool();
            case 'n':
                return this.parseNull();
            default:
                return this.parseNumber();
        }
    }
    parseObject() {
        this.i++; // consume '{'
        const out = {};
        this.skipWhitespace();
        if (this.src.charAt(this.i) === '}') {
            this.i++;
            return out;
        }
        for (;;) {
            this.skipWhitespace();
            if (this.src.charAt(this.i) !== '"') {
                throw new SyntaxError(`parsePythonJSON: expected string key at offset ${this.i}`);
            }
            const key = this.parseString();
            if (Object.prototype.hasOwnProperty.call(out, key)) {
                throw new SyntaxError(`parsePythonJSON: duplicate key "${key}" at offset ${this.i}`);
            }
            this.skipWhitespace();
            if (this.src.charAt(this.i) !== ':') {
                throw new SyntaxError(`parsePythonJSON: expected ':' at offset ${this.i}`);
            }
            this.i++;
            out[key] = this.parseValue();
            this.skipWhitespace();
            const c = this.src.charAt(this.i);
            if (c === ',') {
                this.i++;
                continue;
            }
            if (c === '}') {
                this.i++;
                return out;
            }
            throw new SyntaxError(`parsePythonJSON: expected ',' or '}' at offset ${this.i}`);
        }
    }
    parseArray() {
        this.i++; // consume '['
        const out = [];
        this.skipWhitespace();
        if (this.src.charAt(this.i) === ']') {
            this.i++;
            return out;
        }
        for (;;) {
            out.push(this.parseValue());
            this.skipWhitespace();
            const c = this.src.charAt(this.i);
            if (c === ',') {
                this.i++;
                continue;
            }
            if (c === ']') {
                this.i++;
                return out;
            }
            throw new SyntaxError(`parsePythonJSON: expected ',' or ']' at offset ${this.i}`);
        }
    }
    parseString() {
        if (this.src.charAt(this.i) !== '"') {
            throw new SyntaxError(`parsePythonJSON: expected string at offset ${this.i}`);
        }
        this.i++;
        let out = '';
        while (this.i < this.src.length) {
            const ch = this.src.charAt(this.i);
            if (ch === '"') {
                this.i++;
                return out;
            }
            if (ch === '\\') {
                this.i++;
                const esc = this.src.charAt(this.i);
                this.i++;
                switch (esc) {
                    case '"':
                        out += '"';
                        break;
                    case '\\':
                        out += '\\';
                        break;
                    case '/':
                        out += '/';
                        break;
                    case 'b':
                        out += '\b';
                        break;
                    case 'f':
                        out += '\f';
                        break;
                    case 'n':
                        out += '\n';
                        break;
                    case 'r':
                        out += '\r';
                        break;
                    case 't':
                        out += '\t';
                        break;
                    case 'u': {
                        const hex = this.src.slice(this.i, this.i + 4);
                        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
                            throw new SyntaxError(`parsePythonJSON: invalid \\u escape at offset ${this.i}`);
                        }
                        this.i += 4;
                        const code = parseInt(hex, 16);
                        if (code >= 0xd800 && code <= 0xdbff) {
                            if (this.src.charAt(this.i) === '\\' &&
                                this.src.charAt(this.i + 1) === 'u') {
                                const hex2 = this.src.slice(this.i + 2, this.i + 6);
                                if (!/^[0-9a-fA-F]{4}$/.test(hex2)) {
                                    throw new SyntaxError(`parsePythonJSON: invalid surrogate at offset ${this.i}`);
                                }
                                const low = parseInt(hex2, 16);
                                if (low >= 0xdc00 && low <= 0xdfff) {
                                    this.i += 6;
                                    const cp = 0x10000 +
                                        ((code - 0xd800) << 10) +
                                        (low - 0xdc00);
                                    out += String.fromCodePoint(cp);
                                    break;
                                }
                            }
                        }
                        out += String.fromCharCode(code);
                        break;
                    }
                    default:
                        throw new SyntaxError(`parsePythonJSON: invalid escape \\${esc} at offset ${this.i}`);
                }
            }
            else {
                const code = ch.charCodeAt(0);
                if (code < 0x20) {
                    throw new SyntaxError(`parsePythonJSON: control character in string at offset ${this.i}`);
                }
                out += ch;
                this.i++;
            }
        }
        throw new SyntaxError('parsePythonJSON: unterminated string');
    }
    parseBool() {
        if (this.src.startsWith('true', this.i)) {
            this.i += 4;
            return true;
        }
        if (this.src.startsWith('false', this.i)) {
            this.i += 5;
            return false;
        }
        throw new SyntaxError(`parsePythonJSON: expected bool at offset ${this.i}`);
    }
    parseNull() {
        if (this.src.startsWith('null', this.i)) {
            this.i += 4;
            return null;
        }
        throw new SyntaxError(`parsePythonJSON: expected null at offset ${this.i}`);
    }
    parseNumber() {
        const start = this.i;
        if (this.src.charAt(this.i) === '-')
            this.i++;
        if (this.src.charAt(this.i) === '0') {
            this.i++;
        }
        else if (this.src.charAt(this.i) >= '1' && this.src.charAt(this.i) <= '9') {
            while (this.i < this.src.length) {
                const c = this.src.charAt(this.i);
                if (c < '0' || c > '9')
                    break;
                this.i++;
            }
        }
        else {
            throw new SyntaxError(`parsePythonJSON: expected digit at offset ${this.i}`);
        }
        let isFloat = false;
        if (this.src.charAt(this.i) === '.') {
            isFloat = true;
            this.i++;
            let digits = 0;
            while (this.i < this.src.length) {
                const c = this.src.charAt(this.i);
                if (c < '0' || c > '9')
                    break;
                this.i++;
                digits++;
            }
            if (digits === 0) {
                throw new SyntaxError(`parsePythonJSON: expected digits after '.' at offset ${this.i}`);
            }
        }
        if (this.src.charAt(this.i) === 'e' || this.src.charAt(this.i) === 'E') {
            isFloat = true;
            this.i++;
            const sign = this.src.charAt(this.i);
            if (sign === '+' || sign === '-')
                this.i++;
            let digits = 0;
            while (this.i < this.src.length) {
                const c = this.src.charAt(this.i);
                if (c < '0' || c > '9')
                    break;
                this.i++;
                digits++;
            }
            if (digits === 0) {
                throw new SyntaxError(`parsePythonJSON: expected exponent digits at offset ${this.i}`);
            }
        }
        const literal = this.src.slice(start, this.i);
        if (isFloat) {
            return { __jcsFloat: true, literal };
        }
        const n = Number(literal);
        if (!Number.isFinite(n)) {
            throw new SyntaxError(`parsePythonJSON: non-finite integer literal "${literal}"`);
        }
        return n;
    }
}
