//! Core traits and types for the secretx secrets retrieval library.
//!
//! Backend crates depend on this crate and implement [`SecretStore`] and/or
//! [`SigningBackend`]. Use [`SecretUri::parse`] to parse `secretx:` URIs
//! in backend constructors.

use std::collections::HashMap;
use std::iter::Peekable;
use std::str::Chars;
use zeroize::Zeroizing;

// ── SecretValue ──────────────────────────────────────────────────────────────

/// A secret value whose memory is zeroed on drop.
///
/// Does not implement `Debug`, `Display`, or `Clone` to prevent accidental
/// leakage. Use [`as_bytes`](SecretValue::as_bytes) for comparisons in tests.
///
/// # Why not the `secrecy` crate?
///
/// The [`secrecy`](https://crates.io/crates/secrecy) crate's `Secret<T>` zeroes
/// the outer allocation on drop, which is the same guarantee `Zeroizing<Vec<u8>>`
/// provides here.  For a plain byte buffer that guarantee would be sufficient,
/// and using `secrecy` would be reasonable.
///
/// The problem is [`extract_field`](SecretValue::extract_field) and
/// [`extract_path_field`](SecretValue::extract_path_field).  Secrets are often
/// stored as JSON objects (`{"username":"alice","password":"s3cr3t"}`), so
/// callers frequently need to pull a single string field out of the raw bytes.
/// The obvious implementation calls `serde_json::from_slice`, but serde_json
/// allocates every field value as a plain (non-`Zeroizing`) `String`.  Even
/// after the parsed map is dropped, those allocations are not zeroed: the
/// password lingers in heap memory until the allocator reuses the page.
/// `secrecy::Secret` does not help here — it only zeroes what it directly owns.
///
/// These methods therefore use a hand-rolled JSON scanner that never allocates
/// non-target fields at all.  Only the one requested value is placed into a
/// `Zeroizing` buffer; everything else is scanned and discarded in place.
/// Switching to `secrecy` would either require accepting that leak or keeping
/// the custom scanner anyway, gaining a dependency without simplifying the code.
///
/// **Note on built-in backends:** the network-backed backends (aws-sm, azure-kv,
/// doppler, gcp-sm, vault) use `serde_json` directly rather than these methods,
/// because in those backends the secret arrives in non-Zeroizing heap memory (a
/// `reqwest` response buffer or an SDK-owned `String`) before any parsing begins.
/// The custom scanner cannot retroactively zero memory it does not own, so using
/// it there would add complexity without improving the security boundary.  These
/// methods are most useful when the `SecretValue` originates from a backend that
/// does not pre-leak — e.g. `secretx-file` or `secretx-env` — and the caller
/// needs to extract a JSON field while minimising additional unzeroed copies.
///
/// See the `// ── JSON field extractor` section below for the full rationale.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretValue(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }

    /// Decode as UTF-8 without copying. Fails if not valid UTF-8.
    pub fn as_str(&self) -> Result<&str, SecretError> {
        std::str::from_utf8(&self.0)
            .map_err(|_| SecretError::DecodeFailed("not valid UTF-8".into()))
    }

    /// Parse as a JSON object and extract a single string field.
    ///
    /// Common for secrets that bundle multiple values as JSON,
    /// e.g. `{"username":"foo","password":"bar"}`.
    ///
    /// Uses a hand-rolled JSON scanner so that only the requested field's value
    /// is allocated. A full-tree parser (e.g. serde_json) would allocate copies
    /// of every field value, leaving other secret strings in unzeroized heap
    /// memory even after the parse result is dropped.
    pub fn extract_field(&self, field: &str) -> Result<SecretValue, SecretError> {
        json_extract_string_field(self.as_bytes(), field)
    }

    /// Navigate through nested JSON objects and return the raw bytes of the
    /// value at `path`'s final key as a new `SecretValue`.
    ///
    /// Each key in `path` must exist in the current JSON object.  All
    /// intermediate values (`path[..path.len()-1]`) must be JSON objects.
    /// The final value may be any JSON type.
    ///
    /// # Example (Vault KV v2)
    ///
    /// Given `{"data": {"data": {"password": "s3cret"}}, ...}`,
    /// `extract_path(&["data", "data"])` returns a `SecretValue` containing
    /// the bytes of `{"password": "s3cret"}`.  Call [`SecretValue::extract_field`] on
    /// the result to retrieve a specific secret field.
    pub fn extract_path(&self, path: &[&str]) -> Result<SecretValue, SecretError> {
        let raw = json_navigate(self.as_bytes(), path)?;
        Ok(SecretValue::new(raw.to_vec()))
    }

    /// Navigate through nested JSON objects and extract a string field.
    ///
    /// Equivalent to `self.extract_path(path)?.extract_field(field)` but
    /// avoids an intermediate allocation: the nested object bytes are sliced
    /// from the original input with no copy, and only the target field value
    /// is placed in a `Zeroizing` buffer.
    pub fn extract_path_field(
        &self,
        path: &[&str],
        field: &str,
    ) -> Result<SecretValue, SecretError> {
        let raw = json_navigate(self.as_bytes(), path)?;
        json_extract_string_field(raw, field)
    }
}

// ── JSON scanners ─────────────────────────────────────────────────────────────
//
// There are two complementary hand-rolled JSON scanners in this file.  They are
// NOT duplicates of each other; they handle different operations:
//
//   1. Char-level string extractor (below this comment): used by
//      `extract_field` and `extract_path_field`.  Iterates through a flat
//      `{"key": "value", ...}` object, matches a specific key, then decodes
//      the string value — handling all JSON escape sequences (\n, \t, \uXXXX)
//      and surrogate pairs.  Returns the decoded bytes in a Zeroizing buffer.
//
//   2. Byte-level navigation scanner (below the `// ── Byte-level JSON
//      navigation` comment): used by `extract_path`.  Navigates nested objects
//      by returning `&[u8]` sub-slices of the input WITHOUT allocating or
//      decoding string contents.  Byte-level is used because
//      `Peekable<Chars<'_>>` does not expose byte offsets.
//
// Maintenance contract: the two scanners are independent.  Changes to the
// byte-level scanner do not require changes to the char-level scanner, and
// vice versa.  The char-level scanner owns string decoding (escapes, surrogate
// pairs); the byte-level scanner owns structural navigation (nested objects,
// sub-slice extraction).
//
// Why not serde_json?
// serde_json deserializes all field values into plain (non-Zeroizing) String
// allocations.  Even after the parse result is dropped, those allocations are
// not zeroed, so every other secret string in the object would linger in heap
// memory until the allocator happens to reuse those pages.  These scanners
// avoid that by never touching non-target fields and writing only the target
// value into a Zeroizing buffer.
//
// DO NOT replace these scanners with serde_json, and do not replace SecretValue
// with secrecy::Secret.  The zeroization guarantee is the reason this code
// exists — it is not wheel-reinvention.  See the `SecretValue` doc comment for
// the full explanation.  If a contributor suggests either change, point them
// there.
//
// Future: this logic is a candidate for extraction into a small standalone
// crate (e.g. `zeroizing-json-field`) so the wider Rust secrets ecosystem can
// benefit.  No mainstream JSON crate provides this guarantee today.

/// Extract a single string-valued field from a flat JSON object.
fn json_extract_string_field(bytes: &[u8], field: &str) -> Result<SecretValue, SecretError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| SecretError::DecodeFailed("not valid UTF-8".into()))?;

    let mut chars = s.chars().peekable();

    json_skip_ws(&mut chars);
    json_expect(&mut chars, '{')?;

    // Handle empty object.
    json_skip_ws(&mut chars);
    if chars.peek() == Some(&'}') {
        return Err(SecretError::DecodeFailed(format!(
            "field `{field}` not found"
        )));
    }

    loop {
        // Each iteration: we are positioned at the start of a key string ('"').
        json_expect(&mut chars, '"')?;
        let key = json_parse_string(&mut chars)?;

        json_skip_ws(&mut chars);
        json_expect(&mut chars, ':')?;
        json_skip_ws(&mut chars);

        if key == field {
            if chars.peek() != Some(&'"') {
                return Err(SecretError::DecodeFailed(format!(
                    "field `{field}` is not a string"
                )));
            }
            chars.next(); // consume opening '"'
            let value = json_parse_string(&mut chars)?;
            // Validate post-value structure.  Without this check, trailing
            // garbage immediately after the target field's value is silently
            // ignored, but the same garbage positioned before the target field
            // would cause an error — an asymmetry that is hard to debug.
            json_skip_ws(&mut chars);
            match chars.peek() {
                Some(&',') | Some(&'}') => {}
                Some(&c) => {
                    return Err(SecretError::DecodeFailed(format!(
                        "expected ',' or '}}' after value of field `{field}`, got '{c}'"
                    )));
                }
                None => {
                    return Err(SecretError::DecodeFailed(
                        "unexpected end of input after field value".into(),
                    ));
                }
            }
            return Ok(SecretValue::new(value.into_bytes()));
        }

        // Skip the value for a non-matching key.
        json_skip_value(&mut chars)?;

        // After each pair: expect ',' (more items) or '}' (end of object).
        json_skip_ws(&mut chars);
        match chars.next() {
            Some(',') => {
                json_skip_ws(&mut chars);
                // Guard against trailing comma before '}'.
                if chars.peek() == Some(&'}') {
                    return Err(SecretError::DecodeFailed(
                        "trailing comma in JSON object".into(),
                    ));
                }
            }
            Some('}') => {
                return Err(SecretError::DecodeFailed(format!(
                    "field `{field}` not found"
                )));
            }
            Some(c) => {
                return Err(SecretError::DecodeFailed(format!(
                    "expected ',' or '}}' in JSON object, got '{c}'"
                )));
            }
            None => {
                return Err(SecretError::DecodeFailed(
                    "unexpected end of JSON object".into(),
                ));
            }
        }
    }
}

fn json_skip_ws(chars: &mut Peekable<Chars<'_>>) {
    while matches!(
        chars.peek(),
        Some(' ') | Some('\t') | Some('\n') | Some('\r')
    ) {
        chars.next();
    }
}

fn json_expect(chars: &mut Peekable<Chars<'_>>, expected: char) -> Result<(), SecretError> {
    match chars.next() {
        Some(c) if c == expected => Ok(()),
        Some(c) => Err(SecretError::DecodeFailed(format!(
            "expected '{expected}', got '{c}'"
        ))),
        None => Err(SecretError::DecodeFailed(format!(
            "expected '{expected}', got end of input"
        ))),
    }
}

/// Parse a JSON string after the opening `"` has been consumed.
/// Allocates only the returned `String`; no other heap buffers are created.
fn json_parse_string(chars: &mut Peekable<Chars<'_>>) -> Result<String, SecretError> {
    let mut result = String::new();
    loop {
        match chars.next() {
            None => return Err(SecretError::DecodeFailed("unterminated JSON string".into())),
            Some('"') => return Ok(result),
            Some('\\') => match chars.next() {
                None => {
                    return Err(SecretError::DecodeFailed(
                        "truncated escape in JSON string".into(),
                    ))
                }
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('b') => result.push('\x08'),
                Some('f') => result.push('\x0C'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('u') => {
                    let ch = json_consume_unicode_escape(chars)?;
                    result.push(ch);
                }
                Some(c) => {
                    return Err(SecretError::DecodeFailed(format!(
                        "unknown JSON escape '\\{c}'"
                    )))
                }
            },
            // RFC 8259 §7: U+0000–U+001F must be escaped; a bare control
            // character in a JSON string is invalid.
            Some(c) if (c as u32) < 0x20 => {
                return Err(SecretError::DecodeFailed(format!(
                    "unescaped control character U+{:04X} in JSON string",
                    c as u32
                )));
            }
            Some(c) => result.push(c),
        }
    }
}

/// Consume a `\uXXXX` escape sequence; the `\u` has already been consumed.
///
/// Handles surrogate pairs: if the first code unit is a high surrogate
/// (0xD800–0xDBFF) the immediately following `\uXXXX` low surrogate
/// (0xDC00–0xDFFF) is also consumed and the two are combined into the
/// supplementary Unicode scalar value.  A lone surrogate (either high without
/// a following low, or low without a preceding high) is rejected.
///
/// Returns the decoded Unicode scalar value so callers that are building a
/// string can push it directly.  Callers that are only skipping (not
/// extracting) can discard the return value; validation still runs.
fn json_consume_unicode_escape(chars: &mut Peekable<Chars<'_>>) -> Result<char, SecretError> {
    let hex: String = chars.by_ref().take(4).collect();
    if hex.len() != 4 {
        return Err(SecretError::DecodeFailed(
            "truncated \\uXXXX escape in JSON string".into(),
        ));
    }
    let code = u32::from_str_radix(&hex, 16)
        .map_err(|_| SecretError::DecodeFailed("invalid hex digits in \\uXXXX escape".into()))?;

    if (0xD800..=0xDBFF).contains(&code) {
        // High surrogate: RFC 8259 §7 requires an immediately following
        // \uXXXX low surrogate.  Combine the pair into a supplementary
        // code point: U+10000 + (H - 0xD800) * 0x400 + (L - 0xDC00).
        if chars.next() != Some('\\') || chars.next() != Some('u') {
            return Err(SecretError::DecodeFailed(format!(
                "\\u{code:04X} is a high surrogate not followed by \\uXXXX"
            )));
        }
        let low_hex: String = chars.by_ref().take(4).collect();
        if low_hex.len() != 4 {
            return Err(SecretError::DecodeFailed(
                "truncated \\uXXXX low-surrogate escape".into(),
            ));
        }
        let low = u32::from_str_radix(&low_hex, 16).map_err(|_| {
            SecretError::DecodeFailed("invalid hex digits in \\uXXXX low-surrogate escape".into())
        })?;
        if !(0xDC00..=0xDFFF).contains(&low) {
            return Err(SecretError::DecodeFailed(format!(
                "\\u{code:04X} is a high surrogate but \\u{low:04X} is not a low surrogate"
            )));
        }
        let codepoint = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
        // All valid surrogate pairs produce U+10000..=U+10FFFF which are
        // always valid Unicode scalar values.
        char::from_u32(codepoint).ok_or_else(|| {
            SecretError::DecodeFailed(
                "surrogate pair decoded to invalid Unicode scalar value".into(),
            )
        })
    } else if (0xDC00..=0xDFFF).contains(&code) {
        // Lone low surrogate with no preceding high surrogate.
        Err(SecretError::DecodeFailed(format!(
            "\\u{code:04X} is a lone low surrogate"
        )))
    } else {
        char::from_u32(code).ok_or_else(|| {
            SecretError::DecodeFailed("\\uXXXX escape is not a valid Unicode scalar value".into())
        })
    }
}

/// Skip over a JSON value (string, number, bool, null, array, or object)
/// without allocating its content.
fn json_skip_value(chars: &mut Peekable<Chars<'_>>) -> Result<(), SecretError> {
    match chars.peek().copied() {
        Some('"') => {
            chars.next(); // consume '"'
            json_skip_string(chars)
        }
        Some('t') => json_skip_literal(chars, "true"),
        Some('f') => json_skip_literal(chars, "false"),
        Some('n') => json_skip_literal(chars, "null"),
        Some(c) if c == '-' || c.is_ascii_digit() => json_skip_number(chars),
        Some('[') => json_skip_container(chars, '[', ']'),
        Some('{') => json_skip_container(chars, '{', '}'),
        Some(c) => Err(SecretError::DecodeFailed(format!(
            "unexpected character '{c}' at start of JSON value"
        ))),
        None => Err(SecretError::DecodeFailed(
            "unexpected end of input in JSON value".into(),
        )),
    }
}

/// Skip a JSON string after the opening `"` has been consumed.
///
/// Validates `\uXXXX` escapes including surrogate pairs, consistent with
/// `json_parse_string`. A high surrogate not followed by a low surrogate, or a
/// lone low surrogate, is rejected — invalid JSON is rejected regardless of
/// which field is being extracted.
fn json_skip_string(chars: &mut Peekable<Chars<'_>>) -> Result<(), SecretError> {
    loop {
        match chars.next() {
            None => return Err(SecretError::DecodeFailed("unterminated JSON string".into())),
            Some('"') => return Ok(()),
            Some('\\') => match chars.next() {
                None => {
                    return Err(SecretError::DecodeFailed(
                        "truncated escape in JSON string".into(),
                    ))
                }
                Some('u') => {
                    // Validate the escape (including surrogate pairs) but
                    // discard the decoded char — we are skipping, not
                    // extracting.
                    json_consume_unicode_escape(chars)?;
                }
                Some('"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't') => {}
                Some(c) => {
                    return Err(SecretError::DecodeFailed(format!(
                        "unknown JSON escape '\\{c}'"
                    )));
                }
            },
            // RFC 8259 §7: U+0000–U+001F must be escaped; reject bare
            // control characters in skipped strings too.
            Some(c) if (c as u32) < 0x20 => {
                return Err(SecretError::DecodeFailed(format!(
                    "unescaped control character U+{:04X} in JSON string",
                    c as u32
                )));
            }
            Some(_) => {}
        }
    }
}

fn json_skip_literal(chars: &mut Peekable<Chars<'_>>, literal: &str) -> Result<(), SecretError> {
    for expected in literal.chars() {
        match chars.next() {
            Some(c) if c == expected => {}
            Some(c) => {
                return Err(SecretError::DecodeFailed(format!(
                    "invalid JSON literal: expected '{expected}', got '{c}'"
                )))
            }
            None => {
                return Err(SecretError::DecodeFailed(
                    "unexpected end of input in JSON literal".into(),
                ))
            }
        }
    }
    Ok(())
}

// json_skip_number (char-based, below) and skip_number_b (byte-based, in the
// byte-level navigation section) implement the same RFC 8259 §6 grammar but
// cannot be unified: json_skip_number advances a shared Peekable<Chars>
// iterator and returns (), while skip_number_b takes a positional byte index
// and returns the new position.  The two calling conventions are incompatible.
// If you update one, update the other to match.
fn json_skip_number(chars: &mut Peekable<Chars<'_>>) -> Result<(), SecretError> {
    if chars.peek() == Some(&'-') {
        chars.next();
    }
    // RFC 8259 §6: an integer part (one or more digits) must follow the
    // optional minus sign.  A bare '-' is not a valid JSON number.
    if !chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return Err(SecretError::DecodeFailed(
            "invalid JSON number: expected digit after '-'".into(),
        ));
    }
    // Consume the first integer digit.  RFC 8259 §6: if it is '0', no
    // further digits may appear in the integer part — leading zeros like
    // 01 or 007 are not valid JSON numbers.
    let first = chars.next().expect("peeked above");
    if first == '0' && chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return Err(SecretError::DecodeFailed(
            "invalid JSON number: leading zeros are not allowed".into(),
        ));
    }
    // Consume remaining integer digits.  When first == '0' the leading-zero
    // check above guarantees the next char is not a digit, so this is a no-op.
    while chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        chars.next();
    }
    if chars.peek() == Some(&'.') {
        chars.next();
        // RFC 8259 §6: frac = decimal-point 1*DIGIT — at least one digit
        // must follow the decimal point.  `1.` is not a valid JSON number.
        if !chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return Err(SecretError::DecodeFailed(
                "invalid JSON number: expected digit after decimal point".into(),
            ));
        }
        while chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            chars.next();
        }
    }
    if matches!(chars.peek(), Some('e') | Some('E')) {
        chars.next();
        if matches!(chars.peek(), Some('+') | Some('-')) {
            chars.next();
        }
        // RFC 8259 §6: at least one digit must follow the exponent indicator.
        if !chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            return Err(SecretError::DecodeFailed(
                "invalid JSON number: exponent has no digits".into(),
            ));
        }
        while chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
            chars.next();
        }
    }
    Ok(())
}

/// Skip a JSON array `[...]` or object `{...}`, handling nested structures and
/// strings (which may contain the closing bracket as escaped characters).
///
/// # Limitation: mixed bracket types are not validated
///
/// This function only counts occurrences of the *specific* `open`/`close` pair
/// it was called with.  A structurally invalid input like `[{]}` will be
/// accepted: `[` opens depth 1, `{` is ignored (wrong bracket type), `]`
/// closes depth 0 and returns `Ok`.  The iterator position after the call is
/// correct (we stop at `]`), but the remaining `}` will be unexpected in the
/// caller and will produce a parse error there.
///
/// This is acceptable because `json_extract_string_field` only calls this
/// function to skip non-target field values, not to validate the JSON
/// structure.  The outer loop will detect the malformed trailing `}` and
/// return `DecodeFailed`.  Do not rely on this function as a structural
/// validator for bracket-type matching.
fn json_skip_container(
    chars: &mut Peekable<Chars<'_>>,
    open: char,
    close: char,
) -> Result<(), SecretError> {
    // Consume the opening bracket/brace.
    chars.next();
    let mut depth = 1usize;
    loop {
        match chars.next() {
            None => {
                return Err(SecretError::DecodeFailed(
                    "unterminated JSON container".into(),
                ))
            }
            Some('"') => json_skip_string(chars)?,
            Some(c) if c == open => depth += 1,
            Some(c) if c == close => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            Some(_) => {}
        }
    }
}

// ── Byte-level JSON navigation ────────────────────────────────────────────────
//
// See the "── JSON scanners ──" comment above for the maintenance contract.
//
// These functions provide zero-allocation navigation through nested JSON
// objects.  They track byte positions so they can return `&[u8]` sub-slices of
// the input without decoding string values.  The char-level scanner above this
// section owns string decoding (escapes, surrogate pairs).
//
// Why byte-level and not char-level?
// `Peekable<Chars<'_>>` does not expose byte offsets.  A byte-level scanner
// is safe for JSON because all structural characters ('{', '}', '[', ']',
// ':', ',', '"', '\\') are ASCII (< 0x80) and cannot appear as continuation
// bytes in multi-byte UTF-8 sequences.  Key strings with non-ASCII chars are
// handled by dropping back to `str` for the char boundary.

/// Navigate through `path` in nested JSON objects and return a raw byte slice
/// of the value at the final key.  An empty `path` returns `bytes` unchanged.
fn json_navigate<'a>(bytes: &'a [u8], path: &[&str]) -> Result<&'a [u8], SecretError> {
    let mut current = bytes;
    for key in path {
        current = json_find_value_b(current, key)?;
    }
    Ok(current)
}

/// Find `key` in the JSON object `bytes` and return a raw byte sub-slice of
/// its value.  Leading/trailing whitespace of the value is excluded.
fn json_find_value_b<'a>(bytes: &'a [u8], key: &str) -> Result<&'a [u8], SecretError> {
    // Validate UTF-8 so that scan_string_key_b can safely use str operations.
    if std::str::from_utf8(bytes).is_err() {
        return Err(SecretError::DecodeFailed("not valid UTF-8".into()));
    }

    let mut pos = skip_ws_b(bytes, 0);
    if bytes.get(pos) != Some(&b'{') {
        return Err(SecretError::DecodeFailed("expected JSON object '{'".into()));
    }
    pos += 1;
    pos = skip_ws_b(bytes, pos);

    // Handle empty object.
    if bytes.get(pos) == Some(&b'}') {
        return Err(SecretError::DecodeFailed(format!("key `{key}` not found")));
    }

    loop {
        pos = skip_ws_b(bytes, pos);
        if bytes.get(pos) != Some(&b'"') {
            return Err(SecretError::DecodeFailed("expected '\"' for key".into()));
        }
        let (k, new_pos) = scan_string_key_b(bytes, pos + 1)?;
        pos = new_pos;

        pos = skip_ws_b(bytes, pos);
        if bytes.get(pos) != Some(&b':') {
            return Err(SecretError::DecodeFailed("expected ':' after key".into()));
        }
        pos += 1;
        pos = skip_ws_b(bytes, pos);

        let value_start = pos;
        let value_end = skip_value_b(bytes, pos)?;

        if k == key {
            // skip_value_b stops exactly after the last byte of the value
            // token; no trailing whitespace is included in [value_start..value_end].
            return Ok(&bytes[value_start..value_end]);
        }

        pos = skip_ws_b(bytes, value_end);
        match bytes.get(pos) {
            Some(&b',') => {
                pos += 1;
                pos = skip_ws_b(bytes, pos);
                // Guard against trailing comma.
                if bytes.get(pos) == Some(&b'}') {
                    return Err(SecretError::DecodeFailed(
                        "trailing comma in JSON object".into(),
                    ));
                }
            }
            Some(&b'}') => {
                return Err(SecretError::DecodeFailed(format!("key `{key}` not found")));
            }
            Some(&c) => {
                return Err(SecretError::DecodeFailed(format!(
                    "expected ',' or '}}' in JSON object, got byte {c:#04x}"
                )));
            }
            None => {
                return Err(SecretError::DecodeFailed(
                    "unexpected end of JSON object".into(),
                ));
            }
        }
    }
}

/// Advance past ASCII whitespace; return the new position.
fn skip_ws_b(bytes: &[u8], mut pos: usize) -> usize {
    while matches!(
        bytes.get(pos),
        Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r')
    ) {
        pos += 1;
    }
    pos
}

/// Parse a JSON key string, starting just AFTER the opening `"`.
/// Returns `(decoded_key, byte_position_after_closing_quote)`.
///
/// Handles all JSON string escapes including `\uXXXX` and surrogate pairs.
/// Multi-byte UTF-8 characters in keys are passed through correctly.
fn scan_string_key_b(bytes: &[u8], mut pos: usize) -> Result<(String, usize), SecretError> {
    let mut key = String::new();
    while pos < bytes.len() {
        let b = bytes[pos];
        pos += 1;
        match b {
            b'"' => return Ok((key, pos)),
            b'\\' => {
                if pos >= bytes.len() {
                    return Err(SecretError::DecodeFailed(
                        "truncated escape in JSON key".into(),
                    ));
                }
                let e = bytes[pos];
                pos += 1;
                match e {
                    b'"' => key.push('"'),
                    b'\\' => key.push('\\'),
                    b'/' => key.push('/'),
                    b'b' => key.push('\x08'),
                    b'f' => key.push('\x0C'),
                    b'n' => key.push('\n'),
                    b'r' => key.push('\r'),
                    b't' => key.push('\t'),
                    b'u' => {
                        if pos + 4 > bytes.len() {
                            return Err(SecretError::DecodeFailed(
                                "truncated \\uXXXX in JSON key".into(),
                            ));
                        }
                        let hex = std::str::from_utf8(&bytes[pos..pos + 4]).map_err(|_| {
                            SecretError::DecodeFailed("non-ASCII bytes in \\uXXXX escape".into())
                        })?;
                        let code = u32::from_str_radix(hex, 16).map_err(|_| {
                            SecretError::DecodeFailed("invalid hex digits in \\uXXXX".into())
                        })?;
                        pos += 4;
                        if (0xD800..=0xDBFF).contains(&code) {
                            // High surrogate — must be followed by \uXXXX low surrogate.
                            if bytes.get(pos..pos + 2) != Some(b"\\u") {
                                return Err(SecretError::DecodeFailed(format!(
                                    "\\u{code:04X} is a high surrogate not followed by \\uXXXX"
                                )));
                            }
                            if pos + 6 > bytes.len() {
                                return Err(SecretError::DecodeFailed(
                                    "truncated low-surrogate \\uXXXX".into(),
                                ));
                            }
                            let low_hex =
                                std::str::from_utf8(&bytes[pos + 2..pos + 6]).map_err(|_| {
                                    SecretError::DecodeFailed(
                                        "non-ASCII bytes in low-surrogate \\uXXXX".into(),
                                    )
                                })?;
                            let low = u32::from_str_radix(low_hex, 16).map_err(|_| {
                                SecretError::DecodeFailed(
                                    "invalid hex in low-surrogate \\uXXXX".into(),
                                )
                            })?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(SecretError::DecodeFailed(format!(
                                    "\\u{code:04X} high surrogate not followed by low surrogate (got \\u{low:04X})"
                                )));
                            }
                            let cp = 0x10000u32 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            key.push(char::from_u32(cp).ok_or_else(|| {
                                SecretError::DecodeFailed(
                                    "surrogate pair decoded to invalid scalar".into(),
                                )
                            })?);
                            pos += 6;
                        } else if (0xDC00..=0xDFFF).contains(&code) {
                            return Err(SecretError::DecodeFailed(format!(
                                "\\u{code:04X} is a lone low surrogate"
                            )));
                        } else {
                            key.push(char::from_u32(code).ok_or_else(|| {
                                SecretError::DecodeFailed(
                                    "\\uXXXX decoded to invalid Unicode scalar".into(),
                                )
                            })?);
                        }
                    }
                    _ => {
                        return Err(SecretError::DecodeFailed(format!(
                            "unknown JSON escape '\\{}'",
                            e as char
                        )))
                    }
                }
            }
            b if b < 0x20 => {
                return Err(SecretError::DecodeFailed(format!(
                    "unescaped control character {b:#04x} in JSON key"
                )));
            }
            b if b < 0x80 => {
                // Plain ASCII.
                key.push(b as char);
            }
            _ => {
                // Multi-byte UTF-8 sequence.  UTF-8 validity was confirmed by
                // json_find_value_b; `bytes[pos-1..]` starts at the lead byte.
                let rest = std::str::from_utf8(&bytes[pos - 1..])
                    .expect("UTF-8 validity confirmed at json_find_value_b entry");
                let ch = rest
                    .chars()
                    .next()
                    .expect("non-empty slice has at least one char");
                key.push(ch);
                pos += ch.len_utf8() - 1; // already consumed lead byte above
            }
        }
    }
    Err(SecretError::DecodeFailed("unterminated JSON string".into()))
}

/// Skip a JSON value at `pos` and return the byte position past its last byte.
fn skip_value_b(bytes: &[u8], pos: usize) -> Result<usize, SecretError> {
    match bytes.get(pos) {
        Some(b'"') => skip_string_b(bytes, pos + 1),
        Some(b'{') => skip_container_b(bytes, pos + 1, b'}'),
        Some(b'[') => skip_container_b(bytes, pos + 1, b']'),
        Some(b't') => expect_literal_b(bytes, pos, b"true"),
        Some(b'f') => expect_literal_b(bytes, pos, b"false"),
        Some(b'n') => expect_literal_b(bytes, pos, b"null"),
        Some(&c) if c == b'-' || c.is_ascii_digit() => skip_number_b(bytes, pos),
        Some(&c) => Err(SecretError::DecodeFailed(format!(
            "unexpected byte {c:#04x} at start of JSON value"
        ))),
        None => Err(SecretError::DecodeFailed(
            "unexpected end of input at JSON value".into(),
        )),
    }
}

/// Skip a JSON string body (call after consuming the opening `"`).
/// Returns the byte position past the closing `"`.
fn skip_string_b(bytes: &[u8], mut pos: usize) -> Result<usize, SecretError> {
    while pos < bytes.len() {
        match bytes[pos] {
            b'"' => return Ok(pos + 1),
            b'\\' => {
                pos += 1;
                if pos >= bytes.len() {
                    return Err(SecretError::DecodeFailed(
                        "truncated escape in JSON string".into(),
                    ));
                }
                // For \uXXXX skip 'u' + 4 hex digits.
                //
                // Surrogate pairs (\uHHHH\uLLLL) are NOT validated here: this
                // path skips values without decoding them, and validating
                // surrogates would require hex parsing and lookahead beyond what
                // a byte-level skip warrants.  The char-level skip
                // (json_skip_string, used by extract_field) does validate
                // surrogates.  If surrogate-level validation is needed on the
                // byte-level path, use extract_field instead of extract_path.
                pos += if bytes[pos] == b'u' { 5 } else { 1 };
            }
            // RFC 8259 §7: U+0000–U+001F must be escaped; reject bare control
            // characters in skipped strings, consistent with json_skip_string.
            b if b < 0x20 => {
                return Err(SecretError::DecodeFailed(format!(
                    "unescaped control character {b:#04x} in JSON string"
                )));
            }
            // All other bytes — including multi-byte UTF-8 continuation bytes
            // (≥ 0x80) — are skipped one byte at a time.  They cannot be '"'
            // or '\' (both ASCII), so this is safe.
            _ => pos += 1,
        }
    }
    Err(SecretError::DecodeFailed("unterminated JSON string".into()))
}

/// Skip a JSON `{...}` or `[...]` body (call after consuming the opening
/// bracket).  `close` is the expected closing byte (`b'}'` or `b']'`).
fn skip_container_b(bytes: &[u8], mut pos: usize, close: u8) -> Result<usize, SecretError> {
    let mut depth: u32 = 1;
    while pos < bytes.len() {
        match bytes[pos] {
            b'"' => pos = skip_string_b(bytes, pos + 1)?,
            b'{' | b'[' => {
                depth += 1;
                pos += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    if bytes[pos] != close {
                        return Err(SecretError::DecodeFailed("mismatched JSON brackets".into()));
                    }
                    return Ok(pos + 1);
                }
                pos += 1;
            }
            _ => pos += 1,
        }
    }
    Err(SecretError::DecodeFailed(
        "unterminated JSON container".into(),
    ))
}

/// Verify `bytes[pos..]` starts with `literal` and return `pos + literal.len()`.
fn expect_literal_b(bytes: &[u8], pos: usize, literal: &[u8]) -> Result<usize, SecretError> {
    let end = pos + literal.len();
    if bytes.get(pos..end) == Some(literal) {
        Ok(end)
    } else {
        Err(SecretError::DecodeFailed(format!(
            "expected JSON literal `{}`",
            std::str::from_utf8(literal).unwrap_or("?")
        )))
    }
}

/// Skip a JSON number starting at `pos` and return the position past its end.
///
/// Implements the same RFC 8259 §6 grammar as `json_skip_number` (char-based)
/// but operates on a positional byte index rather than a `Peekable<Chars>`
/// iterator.  The two cannot be unified — see the comment above
/// `json_skip_number` for the reason.  If you update one, update the other.
fn skip_number_b(bytes: &[u8], mut pos: usize) -> Result<usize, SecretError> {
    if bytes.get(pos) == Some(&b'-') {
        pos += 1;
    }
    if !bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        return Err(SecretError::DecodeFailed(
            "invalid JSON number: expected digit".into(),
        ));
    }
    // Consume the first integer digit.  RFC 8259 §6: if it is '0', no
    // further digits may appear in the integer part — leading zeros like
    // 01 or 007 are not valid JSON numbers.
    let first = bytes[pos];
    pos += 1;
    if first == b'0' && bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        return Err(SecretError::DecodeFailed(
            "invalid JSON number: leading zeros are not allowed".into(),
        ));
    }
    while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
        pos += 1;
    }
    if bytes.get(pos) == Some(&b'.') {
        pos += 1;
        // RFC 8259: at least one digit must follow the decimal point.
        if !bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            return Err(SecretError::DecodeFailed(
                "invalid JSON number: expected digit after '.'".into(),
            ));
        }
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
    }
    if matches!(bytes.get(pos), Some(b'e') | Some(b'E')) {
        pos += 1;
        if matches!(bytes.get(pos), Some(b'+') | Some(b'-')) {
            pos += 1;
        }
        // RFC 8259: at least one digit must follow the exponent marker.
        if !bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            return Err(SecretError::DecodeFailed(
                "invalid JSON number: expected digit in exponent".into(),
            ));
        }
        while bytes.get(pos).is_some_and(u8::is_ascii_digit) {
            pos += 1;
        }
    }
    Ok(pos)
}

// ── SecretError ───────────────────────────────────────────────────────────────

/// Errors returned by secret store operations.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// Backend returned no secret for this name/path.
    #[error("secret not found")]
    NotFound,

    /// Backend encountered a permanent error — retrying **will not** help.
    ///
    /// Examples: authentication failure, permission denied, malformed
    /// request, the named secret was deleted.  Callers should surface this
    /// to the operator or abort rather than retrying automatically.
    ///
    /// For transient failures where a retry may succeed (network timeouts,
    /// 5xx responses, temporary outages), use [`Unavailable`](SecretError::Unavailable).
    #[error("backend `{backend}` error: {source}")]
    Backend {
        backend: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// URI was syntactically invalid or named an unknown/disabled backend.
    #[error("invalid URI: {0}")]
    InvalidUri(String),

    /// Secret was present but could not be decoded as expected.
    #[error("decode failed: {0}")]
    DecodeFailed(String),

    /// Backend is temporarily unavailable — retrying **may** succeed.
    ///
    /// Examples: network timeout, DNS failure, connection refused, HTTP 5xx
    /// from a remote secrets service.  Callers should implement retry with
    /// back-off rather than failing immediately.
    ///
    /// For permanent errors that will not resolve on retry, use
    /// [`Backend`](SecretError::Backend).
    #[error("backend `{backend}` unavailable: {source}")]
    Unavailable {
        backend: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

// ── SecretUri helpers ─────────────────────────────────────────────────────────

/// Percent-decode a URI component string (path segment or query value).
///
/// Decodes `%XX` escape sequences where `XX` is a pair of hex digits.
/// Returns `Err(SecretError::InvalidUri)` if a `%` is not followed by two
/// valid hex digits.
fn percent_decode(s: &str) -> Result<String, SecretError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(SecretError::InvalidUri(format!(
                    "incomplete percent-encoding at position {i} in `{s}`"
                )));
            }
            let hi = hex_digit(bytes[i + 1]).ok_or_else(|| {
                SecretError::InvalidUri(format!(
                    "invalid percent-encoding `%{}{}` at position {i} in `{s}`",
                    bytes[i + 1] as char,
                    bytes[i + 2] as char
                ))
            })?;
            let lo = hex_digit(bytes[i + 2]).ok_or_else(|| {
                SecretError::InvalidUri(format!(
                    "invalid percent-encoding `%{}{}` at position {i} in `{s}`",
                    bytes[i + 1] as char,
                    bytes[i + 2] as char
                ))
            })?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| {
        SecretError::InvalidUri(format!(
            "percent-decoded bytes in `{s}` are not valid UTF-8"
        ))
    })
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── SecretUri ─────────────────────────────────────────────────────────────────

/// A parsed `secretx:` URI.
///
/// All backend `from_uri` constructors should parse with this type rather than
/// rolling their own string splitting.
///
/// # URI structure
///
/// ```text
/// secretx:<backend>:<path>[?key=val&key2=val2]
/// ```
///
/// Absolute file paths use a leading `/` in the path component:
///
/// ```text
/// secretx:file:/etc/secrets/key   →  backend="file", path="/etc/secrets/key"
/// secretx:file:relative/path      →  backend="file", path="relative/path"
/// ```
///
/// # Field access
///
/// All fields are private. Use the accessor methods [`SecretUri::backend`],
/// [`SecretUri::path`], and [`SecretUri::param`] to read URI components.
/// This preserves the ability to change the internal representation (e.g.
/// multi-value params or a different map type) without a breaking API change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretUri {
    backend: String,
    path: String,
    params: HashMap<String, String>,
}

impl SecretUri {
    const SCHEME: &'static str = "secretx:";

    /// Parse a `secretx:` URI.
    ///
    /// The format is `secretx:<backend>:<path>[?<params>]`.  Examples:
    ///
    /// ```text
    /// secretx:env:MY_VAR
    /// secretx:file:/etc/secrets/key      (absolute path)
    /// secretx:file:relative/key          (relative path)
    /// secretx:aws-sm:prod/db-password
    /// secretx:vault:secret/myapp?field=password
    /// ```
    ///
    /// Returns [`SecretError::InvalidUri`] if the URI does not start with
    /// `secretx:`, has an empty backend component, or contains invalid
    /// percent-encoding in the path or query parameters.
    pub fn parse(uri: &str) -> Result<Self, SecretError> {
        // Provide a helpful error for the legacy secretx://backend/path format.
        if uri.starts_with("secretx://") {
            return Err(SecretError::InvalidUri(format!(
                "URI uses the old `secretx://backend/path` format; \
                 use `secretx:backend:path` instead (see MIGRATION.md): {uri}"
            )));
        }

        let rest = uri.strip_prefix(Self::SCHEME).ok_or_else(|| {
            SecretError::InvalidUri(format!("URI must start with `secretx:`, got: {uri}"))
        })?;

        // Strip the query string before splitting on ':'.
        let (backend_and_path, query_part) = match rest.find('?') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };

        // Split backend name from path on the first ':'.
        //   secretx:env:MY_VAR           →  backend="env",  path="MY_VAR"
        //   secretx:file:/etc/key        →  backend="file", path="/etc/key"
        //   secretx:aws-sm:prod/key      →  backend="aws-sm", path="prod/key"
        // The path may itself contain ':' (e.g. AWS ARNs); only the first ':'
        // is the backend/path separator.
        let (backend, raw_path) = match backend_and_path.find(':') {
            Some(i) => (&backend_and_path[..i], &backend_and_path[i + 1..]),
            None => (backend_and_path, ""),
        };

        if backend.is_empty() {
            return Err(SecretError::InvalidUri(format!(
                "missing backend name in URI: {uri}"
            )));
        }

        let path = percent_decode(raw_path)?;

        // Parse query parameters, percent-decoding both keys and values.
        // Duplicate keys are silently resolved with last-wins semantics
        // (HashMap::insert overwrites).  No secretx URI uses duplicate keys
        // intentionally; if a URI is malformed with duplicates, the last value
        // wins rather than returning an error.
        let mut params = HashMap::new();
        if let Some(q) = query_part {
            for pair in q.split('&').filter(|s| !s.is_empty()) {
                match pair.find('=') {
                    Some(i) => {
                        let key = percent_decode(&pair[..i])?;
                        let val = percent_decode(&pair[i + 1..])?;
                        params.insert(key, val);
                    }
                    None => {
                        params.insert(percent_decode(pair)?, String::new());
                    }
                }
            }
        }

        Ok(SecretUri {
            backend: backend.to_string(),
            path,
            params,
        })
    }

    /// Return the backend name, e.g. `"aws-sm"`, `"file"`, `"env"`.
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Return the backend-specific path component of the URI.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Return a query parameter value by key, or `None` if absent.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }
}

// ── SecretStore ───────────────────────────────────────────────────────────────

/// A backend that retrieves and stores secrets.
///
/// Implement this trait in a backend crate. Provide a `from_uri` constructor
/// as a plain method (not part of this trait) that calls [`SecretUri::parse`]
/// and validates the backend component. URI dispatch is handled by
/// `secretx::from_uri` in the umbrella crate.
///
/// Each `SecretStore` instance is bound to exactly one secret, identified by
/// the URI passed to `from_uri`. There is no key parameter on `get`; which
/// secret is returned is determined entirely by the URI, not by the call site.
///
/// # Threading
///
/// The trait requires `Send + Sync` because daemons hold `Arc<dyn SecretStore>`
/// in application state shared across many concurrent async tasks. `Send` lets
/// futures that call `get` or `refresh` be moved across threads by a
/// work-stealing runtime (Tokio). `Sync` lets the same `Arc` be accessed from
/// multiple tasks simultaneously without additional locking.
///
/// Network backends (Vault, AWS, GCP) hold an HTTP client that is itself
/// `Send + Sync`, so these bounds don't constrain implementors in practice.
/// Backends that need mutable internal state should use interior mutability
/// (`Mutex`, `RwLock`, or atomics) rather than `&mut self`.
///
/// # Why `async_trait` and not native async-fn-in-trait?
///
/// Native async-fn-in-trait (stable since Rust 1.75) produces unnameable
/// associated future types, which makes `Box<dyn SecretStore>` and
/// `Arc<dyn SecretStore>` impossible without additional machinery
/// (e.g. the `dynosaur` crate or manual `DynSecretStore` wrappers).
/// Since callers store backends as `Arc<dyn SecretStore>`, `async_trait`
/// is the correct choice for this public API. The boxing overhead is
/// incurred once per `get`/`refresh` call, which is acceptable for
/// network-bound backends.
#[async_trait::async_trait]
pub trait SecretStore: Send + Sync {
    /// Retrieve the secret.
    async fn get(&self) -> Result<SecretValue, SecretError>;

    /// Force a fresh fetch from the source, bypassing any cache layer, and
    /// return the new value.
    async fn refresh(&self) -> Result<SecretValue, SecretError>;
}

/// A [`SecretStore`] that also supports writing.
///
/// Implement this trait in addition to [`SecretStore`] for backends that can
/// persist new secret values. Read-only backends (`env`, `bitwarden`, etc.)
/// implement only `SecretStore`.
///
/// # Why a separate trait?
///
/// Not all backends support writes. Putting `put` in the base `SecretStore`
/// trait would force every read-only backend to implement a stub that returns
/// an error — deferring a type-level contract to a runtime failure. The
/// subtrait makes the write capability explicit at compile time: callers that
/// need to write hold `Arc<dyn WritableSecretStore>`; callers that only read
/// hold `Arc<dyn SecretStore>`.
///
/// # Implementation contract
///
/// Implementors must uphold these invariants:
///
/// - **Durability**: when `put` returns `Ok(())`, the value is durably stored.
///   A subsequent call to `get` on the same or a different instance pointing
///   at the same URI must return the written value (modulo cache TTL).
/// - **Atomicity**: a reader must never observe a partially-written secret.
///   Use an atomic rename (temp-file-then-rename) for file backends, or the
///   cloud API's native put-then-publish semantics for remote backends.
/// - **Failure isolation**: if `put` returns `Err`, the previously stored
///   value must remain intact and readable. A failed write must not leave the
///   secret in a corrupted or empty state.
/// - **No silent truncation**: never coerce or truncate the value. Return
///   `Err` if the backend cannot store the full value as provided.
#[async_trait::async_trait]
pub trait WritableSecretStore: SecretStore {
    /// Write or update the secret. The parent directory (for file backends)
    /// or the remote namespace (for cloud backends) must already exist.
    async fn put(&self, value: SecretValue) -> Result<(), SecretError>;
}

// ── SigningBackend ────────────────────────────────────────────────────────────

/// Key algorithm used by a [`SigningBackend`].
///
/// This enum is `#[non_exhaustive]` so that new algorithms (e.g. P-384,
/// Ed448) can be added in a minor version without breaking downstream
/// code that matches on it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
    RsaPss2048Sha256,
}

/// A signing backend where the private key never leaves the HSM.
///
/// Implemented by AWS KMS, Azure Key Vault HSM, PKCS#11, wolfHSM, and local
/// key backends. Call sites are identical regardless of backend.
///
/// # Threading
///
/// Requires `Send + Sync` for the same reasons as [`SecretStore`]: callers
/// hold `Arc<dyn SigningBackend>` and call `sign` from concurrent async tasks.
/// HSM backends that use a non-thread-safe C library should protect internal
/// state with a `Mutex` rather than opting out of `Send + Sync`.
///
/// # Why `async_trait`?
///
/// See [`SecretStore`] — the same rationale applies. `Arc<dyn SigningBackend>`
/// requires object-safe async methods, which native AFIT does not yet provide
/// without extra crates.
#[async_trait::async_trait]
pub trait SigningBackend: Send + Sync {
    /// Sign `message` using the backend key. Returns raw signature bytes.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError>;

    /// Return the public key as DER-encoded SubjectPublicKeyInfo.
    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError>;

    /// Key algorithm identifier.
    ///
    /// Returns an error if the backend cannot determine the algorithm (e.g. the
    /// HSM is offline).  For backends where the algorithm is fixed at
    /// construction time (AWS KMS, local-signing) this always returns `Ok`.
    ///
    /// # Blocking note
    ///
    /// This method is synchronous.  HSM-backed implementations (e.g. PKCS#11)
    /// may open an HSM session on the first call to detect the key type, which
    /// can block the calling thread for tens of milliseconds.  If you are
    /// calling this from async code and the algorithm is not yet cached, prefer
    /// calling [`sign`](SigningBackend::sign) or
    /// [`public_key_der`](SigningBackend::public_key_der) first — those methods
    /// use `spawn_blocking` and populate the algorithm cache as a side effect.
    fn algorithm(&self) -> Result<SigningAlgorithm, SecretError>;
}

// ── Blocking adapter ─────────────────────────────────────────────────────────

/// Run an async block on a dedicated scoped thread with its own single-threaded
/// tokio runtime.
///
/// This is the correct pattern for backends that need to execute async code
/// synchronously at construction time (e.g. AWS client initialization via
/// `aws_config::load_from_env`).  Unlike `block_in_place` or `Handle::block_on`,
/// this never panics when called from within an existing `current_thread` runtime
/// because the async work runs on a *new* OS thread with its *own* runtime.
///
/// # Errors
///
/// Returns `Err(SecretError::Backend)` if the tokio runtime cannot be built or
/// if the spawned thread panics.  The `backend` argument is included in the
/// error for diagnostics.
#[cfg(feature = "blocking")]
pub fn run_on_new_thread<F, Fut, T>(f: F, backend: &'static str) -> Result<T, SecretError>
where
    F: FnOnce() -> Fut + Send,
    Fut: std::future::Future<Output = Result<T, SecretError>>,
    T: Send,
{
    let mut result: Option<Result<T, SecretError>> = None;
    std::thread::scope(|s| {
        let join = s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| SecretError::Backend {
                    backend,
                    source: e.into(),
                })
                .and_then(|rt| rt.block_on(f()))
        });
        result = Some(join.join().unwrap_or_else(|_| {
            Err(SecretError::Backend {
                backend,
                source: "client init thread panicked".into(),
            })
        }));
    });
    result.expect("scope always sets result before exiting")
}

/// Synchronous wrapper for [`SecretStore::get`].
///
/// Works both inside an existing tokio runtime and outside one (creates a
/// single-threaded runtime for the call).  When called from within an existing
/// runtime the call is offloaded to a scoped OS thread with its own runtime so
/// that `block_on` does not panic.
///
/// Call [`SecretStore::get`] from a synchronous context.
///
/// When called outside of any tokio runtime a single-threaded runtime is built
/// on the calling thread. When called from inside an existing runtime, a scoped
/// thread with its own single-threaded runtime is spawned.
///
/// # Panics
/// Does not panic in normal use.  Panics only if the spawned helper thread
/// itself panics (i.e. if tokio runtime construction fails).
///
/// # Limitations
///
/// The scoped runtime is a **fresh, isolated runtime** that lasts only for the
/// duration of the `get` call. If the inner store (or a wrapper like
/// `CachingStore`) internally calls `tokio::spawn` or
/// `tokio::task::spawn_blocking`, those tasks run on the scoped thread's
/// runtime and are **silently dropped** when `block_on` returns. Do not use
/// `get_blocking` with stores that depend on background tasks surviving across
/// calls (e.g. connection-pool health-check tasks, re-auth loops).
#[cfg(feature = "blocking")]
pub fn get_blocking<S: SecretStore + ?Sized>(store: &S) -> Result<SecretValue, SecretError> {
    // When called from outside any tokio runtime, spin up a one-shot
    // current-thread runtime directly on this thread.
    //
    // When called from inside an existing runtime (current_thread or
    // multi-thread), block_on would panic if called on the same thread.
    // Instead, use std::thread::scope to spawn a scoped thread that borrows
    // `store` and `name` safely. The scope guarantees the thread is joined
    // before it exits, so no lifetime transmutation is needed.
    match tokio::runtime::Handle::try_current() {
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SecretError::Backend {
                backend: "blocking",
                source: e.into(),
            })?
            .block_on(store.get()),
        Ok(_) => {
            let mut result: Option<Result<SecretValue, SecretError>> = None;
            std::thread::scope(|s| {
                let join = s.spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| SecretError::Backend {
                            backend: "blocking",
                            source: e.into(),
                        })?
                        .block_on(store.get())
                });
                result = Some(join.join().unwrap_or_else(|_| {
                    Err(SecretError::Backend {
                        backend: "blocking",
                        source: "get_blocking thread panicked".into(),
                    })
                }));
            });
            result.expect("scope always sets result before exiting")
        }
    }
}

// ── Backend registration ──────────────────────────────────────────────────────

/// Registration entry for a [`SecretStore`] backend.
pub struct BackendRegistration {
    /// Backend scheme name (e.g. `"env"`, `"file"`, `"aws-sm"`).
    pub name: &'static str,
    /// Factory function: construct a backend from a URI string.
    pub factory: fn(&str) -> Result<std::sync::Arc<dyn SecretStore>, SecretError>,
}
inventory::collect!(BackendRegistration);

/// Registration entry for a [`WritableSecretStore`] backend.
pub struct WritableBackendRegistration {
    /// Backend scheme name.
    pub name: &'static str,
    /// Factory function: construct a writable backend from a URI string.
    pub factory: fn(&str) -> Result<std::sync::Arc<dyn WritableSecretStore>, SecretError>,
}
inventory::collect!(WritableBackendRegistration);

/// Registration entry for a [`SigningBackend`] backend.
pub struct SigningBackendRegistration {
    /// Backend scheme name.
    pub name: &'static str,
    /// Factory function: construct a signing backend from a URI string.
    pub factory: fn(&str) -> Result<std::sync::Arc<dyn SigningBackend>, SecretError>,
}
inventory::collect!(SigningBackendRegistration);

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // SecretValue tests

    #[test]
    fn secret_value_as_bytes() {
        let v = SecretValue::new(b"hello".to_vec());
        assert_eq!(v.as_bytes(), b"hello");
    }

    #[test]
    fn secret_value_as_str() {
        let v = SecretValue::new(b"hello".to_vec());
        assert_eq!(v.as_str().unwrap(), "hello");
    }

    #[test]
    fn secret_value_as_str_invalid_utf8() {
        let v = SecretValue::new(vec![0xff, 0xfe]);
        assert!(matches!(v.as_str(), Err(SecretError::DecodeFailed(_))));
    }

    #[test]
    fn extract_field_ok() {
        let v = SecretValue::new(br#"{"password":"hunter2","user":"alice"}"#.to_vec());
        let pw = v.extract_field("password").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    #[test]
    fn extract_field_missing() {
        let v = SecretValue::new(br#"{"user":"alice"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_field_not_string() {
        let v = SecretValue::new(br#"{"count":42}"#.to_vec());
        assert!(matches!(
            v.extract_field("count"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_field_invalid_json() {
        let v = SecretValue::new(b"not json".to_vec());
        assert!(matches!(
            v.extract_field("x"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    // RFC 8259 §7: surrogate pair \uHHHH\uLLLL must decode to the correct
    // supplementary code point.  Oracle: U+1F600 (GRINNING FACE) is 😀;
    // its UTF-8 encoding 0xF0 0x9F 0x98 0x80 is independent of this code.
    #[test]
    fn extract_field_surrogate_pair() {
        // \uD83D\uDE00 is the surrogate pair for U+1F600 (😀)
        let v = SecretValue::new(br#"{"pw":"\uD83D\uDE00"}"#.to_vec());
        let pw = v.extract_field("pw").unwrap();
        assert_eq!(pw.as_bytes(), "😀".as_bytes());
    }

    // \uD800 alone (no follow-up low surrogate) must be rejected.
    #[test]
    fn extract_field_lone_high_surrogate() {
        let v = SecretValue::new(br#"{"pw":"\uD800"}"#.to_vec());
        assert!(matches!(
            v.extract_field("pw"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    // \uDC00 alone (no preceding high surrogate) must be rejected.
    #[test]
    fn extract_field_lone_low_surrogate() {
        let v = SecretValue::new(br#"{"pw":"\uDC00"}"#.to_vec());
        assert!(matches!(
            v.extract_field("pw"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    // High surrogate followed by a non-low-surrogate \uXXXX must be rejected.
    #[test]
    fn extract_field_high_surrogate_wrong_follow() {
        // \uD800\u0041 — A is not a low surrogate
        let v = SecretValue::new(br#"{"pw":"\uD800\u0041"}"#.to_vec());
        assert!(matches!(
            v.extract_field("pw"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    // High surrogate followed by a non-\u sequence must be rejected.
    #[test]
    fn extract_field_high_surrogate_no_follow() {
        // \uD800abc — 'a' is not the start of \uXXXX
        let v = SecretValue::new(br#"{"pw":"\uD800abc"}"#.to_vec());
        assert!(matches!(
            v.extract_field("pw"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    // Surrogate validation in the *skip* path (non-extracted fields).
    // These test that json_skip_string validates surrogates consistently with
    // json_parse_string — invalid JSON is rejected regardless of which field
    // the invalid sequence appears in.

    #[test]
    fn skip_field_lone_high_surrogate_rejected() {
        // "other" field has lone high surrogate; "password" is valid.
        // extract_field must fail even though the targeted field is fine.
        let v = SecretValue::new(br#"{"other":"\uD800","password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_field_lone_low_surrogate_rejected() {
        let v = SecretValue::new(br#"{"other":"\uDC00","password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_field_surrogate_pair_valid() {
        // Valid surrogate pair in a non-extracted field must not cause failure.
        // \uD83D\uDE00 = U+1F600 (😀)
        let v = SecretValue::new(br#"{"emoji":"\uD83D\uDE00","password":"hunter2"}"#.to_vec());
        let pw = v.extract_field("password").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    // Malformed JSON number validation (json_skip_number).
    // Oracle: RFC 8259 §6 — exponent must contain at least one digit.

    // RFC 8259 §6: an integer part must follow the optional minus.
    // A bare '-' with no digits is not a valid JSON number.
    #[test]
    fn skip_number_bare_minus_rejected() {
        let v = SecretValue::new(br#"{"count":-,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_bare_exponent_rejected() {
        // "count" has an exponent with no digits — invalid per RFC 8259.
        let v = SecretValue::new(br#"{"count":1e,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_signed_exponent_no_digits_rejected() {
        let v = SecretValue::new(br#"{"count":1e+,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_valid_exponent_accepted() {
        // RFC 8259-valid exponent must not cause failure.
        let v = SecretValue::new(br#"{"count":1e3,"password":"hunter2"}"#.to_vec());
        let pw = v.extract_field("password").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    // RFC 8259 §6: a non-zero integer part must not have leading zeros.
    // Oracle: RFC 8259 §6 grammar — int = zero / (digit1-9 *DIGIT).
    // Any real JSON parser (jq, Python json.loads) rejects 01 and 007.

    #[test]
    fn skip_number_leading_zero_two_digits_rejected() {
        // 01 — leading zero in front of non-zero digit, invalid per RFC 8259.
        let v = SecretValue::new(br#"{"count":01,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_leading_zero_multi_digit_rejected() {
        // 007 — leading zeros, invalid per RFC 8259.
        let v = SecretValue::new(br#"{"count":007,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_bare_zero_accepted() {
        // 0 alone is valid per RFC 8259 (zero = %x30).
        let v = SecretValue::new(br#"{"count":0,"password":"hunter2"}"#.to_vec());
        let pw = v.extract_field("password").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    #[test]
    fn skip_number_negative_leading_zero_rejected() {
        // -01 — leading zero after minus, invalid per RFC 8259.
        let v = SecretValue::new(br#"{"count":-01,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_negative_zero_accepted() {
        // -0 is a valid JSON number (negative zero).
        let v = SecretValue::new(br#"{"count":-0,"password":"hunter2"}"#.to_vec());
        let pw = v.extract_field("password").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    // RFC 8259 §6: frac = decimal-point 1*DIGIT — digit(s) required after '.'.
    // Oracle: Python json.loads('{"x":1.}') raises ValueError; jq raises error.

    #[test]
    fn skip_number_no_fractional_digits_rejected() {
        // 1. — decimal point with no fractional digits, invalid per RFC 8259.
        let v = SecretValue::new(br#"{"count":1.,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_negative_no_fractional_digits_rejected() {
        // -1. — same violation after a minus sign.
        let v = SecretValue::new(br#"{"count":-1.,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_zero_no_fractional_digits_rejected() {
        // 0. — leading zero with decimal point but no fractional digit.
        let v = SecretValue::new(br#"{"count":0.,"password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_number_fractional_digits_accepted() {
        // 1.5 — valid decimal number must not cause failure.
        let v = SecretValue::new(br#"{"count":1.5,"password":"hunter2"}"#.to_vec());
        let pw = v.extract_field("password").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    // RFC 8259 §7: unknown single-char escapes (e.g. \z) are invalid.
    // json_skip_string must reject them consistently with json_parse_string.

    #[test]
    fn skip_field_unknown_escape_rejected() {
        // \z is not a valid JSON escape.  Extracting "password" from a document
        // where "other" contains \z must fail — invalid JSON is invalid regardless
        // of which field is the extraction target.
        let v = SecretValue::new(br#"{"other":"\z","password":"hunter2"}"#.to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn skip_field_all_valid_single_char_escapes_accepted() {
        // All eight valid single-char escapes in a skipped field must not fail.
        // Oracle: RFC 8259 §7 — the allowed escapes are \" \\ \/ \b \f \n \r \t.
        let v = SecretValue::new(br#"{"other":"\"\\\/\b\f\n\r\t","password":"hunter2"}"#.to_vec());
        let pw = v.extract_field("password").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    // RFC 8259 §7: U+0000–U+001F are control characters that must be escaped.
    // Oracle: RFC 8259 §7 grammar — unescaped = %x20-21 / %x23-5B / %x5D-10FFFF.
    // Python json.loads('{"k":"\x00"}') raises ValueError.

    #[test]
    fn extract_field_null_byte_in_value_rejected() {
        // U+0000 (NUL) directly in a JSON string value is invalid per RFC 8259 §7.
        let v = SecretValue::new(b"{\"key\":\"val\x00ue\"}".to_vec());
        assert!(matches!(
            v.extract_field("key"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_field_control_char_soh_rejected() {
        // U+0001 (SOH) — lowest non-null control character.
        let v = SecretValue::new(b"{\"key\":\"\x01\"}".to_vec());
        assert!(matches!(
            v.extract_field("key"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_field_control_char_us_rejected() {
        // U+001F (US) — highest control character in the prohibited range.
        let v = SecretValue::new(b"{\"key\":\"\x1f\"}".to_vec());
        assert!(matches!(
            v.extract_field("key"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_field_space_accepted() {
        // U+0020 (SPACE) is the first non-control character; must be accepted.
        let v = SecretValue::new(b"{\"key\":\"abc def\"}".to_vec());
        assert_eq!(v.extract_field("key").unwrap().as_bytes(), b"abc def");
    }

    // Trailing garbage after target field value.
    // Oracle: the same input with a different target field order must fail
    // consistently regardless of whether the garbage comes before or after
    // the target field.

    #[test]
    fn extract_field_trailing_garbage_first_field_rejected() {
        // Target field is first; garbage appears before the closing '}'.
        let v = SecretValue::new(br#"{"password":"hunter2" GARBAGE}"#.to_vec());
        assert!(
            matches!(
                v.extract_field("password"),
                Err(SecretError::DecodeFailed(_))
            ),
            "trailing garbage after first field must be rejected"
        );
    }

    #[test]
    fn extract_field_trailing_garbage_last_field_rejected() {
        // Target field is last; garbage appears after its value.
        let v = SecretValue::new(br#"{"other":"x","password":"hunter2" GARBAGE}"#.to_vec());
        assert!(
            matches!(
                v.extract_field("password"),
                Err(SecretError::DecodeFailed(_))
            ),
            "trailing garbage after last field must be rejected"
        );
    }

    #[test]
    fn skip_field_control_char_in_other_field_rejected() {
        // Control char in a skipped field must be caught even when extracting
        // a different field — invalid JSON is invalid regardless of target.
        let v = SecretValue::new(b"{\"other\":\"\x01bad\",\"password\":\"hunter2\"}".to_vec());
        assert!(matches!(
            v.extract_field("password"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    // SecretUri tests

    #[test]
    fn uri_env() {
        let u = SecretUri::parse("secretx:env:MY_SECRET").unwrap();
        assert_eq!(u.backend, "env");
        assert_eq!(u.path, "MY_SECRET");
        assert!(u.params.is_empty());
    }

    #[test]
    fn uri_file_relative() {
        let u = SecretUri::parse("secretx:file:relative/path/key").unwrap();
        assert_eq!(u.backend, "file");
        assert_eq!(u.path, "relative/path/key");
    }

    #[test]
    fn uri_file_absolute() {
        let u = SecretUri::parse("secretx:file:/etc/secrets/key").unwrap();
        assert_eq!(u.backend, "file");
        assert_eq!(u.path, "/etc/secrets/key");
    }

    #[test]
    fn uri_aws_sm_with_params() {
        let u =
            SecretUri::parse("secretx:aws-sm:prod/signing-key?field=password&version=AWSCURRENT")
                .unwrap();
        assert_eq!(u.backend, "aws-sm");
        assert_eq!(u.path, "prod/signing-key");
        assert_eq!(u.param("field"), Some("password"));
        assert_eq!(u.param("version"), Some("AWSCURRENT"));
    }

    #[test]
    fn uri_pkcs11_with_lib() {
        let u = SecretUri::parse("secretx:pkcs11:0/my-key?lib=/usr/lib/libsofthsm2.so").unwrap();
        assert_eq!(u.backend, "pkcs11");
        assert_eq!(u.path, "0/my-key");
        assert_eq!(u.param("lib"), Some("/usr/lib/libsofthsm2.so"));
    }

    #[test]
    fn uri_single_segment_path() {
        let u = SecretUri::parse("secretx:wolfhsm:my-key").unwrap();
        assert_eq!(u.backend, "wolfhsm");
        assert_eq!(u.path, "my-key");
    }

    #[test]
    fn uri_empty_path() {
        let u = SecretUri::parse("secretx:wolfhsm:").unwrap();
        assert_eq!(u.backend, "wolfhsm");
        assert_eq!(u.path, "");
    }

    #[test]
    fn uri_wrong_scheme() {
        assert!(matches!(
            SecretUri::parse("https://example.com/secret"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn uri_legacy_authority_format_gives_helpful_error() {
        let result = SecretUri::parse("secretx://env/MY_VAR");
        match result {
            Err(SecretError::InvalidUri(msg)) => {
                assert!(
                    msg.contains("secretx://backend/path"),
                    "error must name the old format, got: {msg}"
                );
                assert!(
                    msg.contains("MIGRATION.md"),
                    "error must reference MIGRATION.md, got: {msg}"
                );
            }
            Err(e) => panic!("expected InvalidUri, got: {e}"),
            Ok(_) => panic!("expected Err, got Ok"),
        }
    }

    #[test]
    fn uri_empty_backend() {
        assert!(matches!(
            SecretUri::parse("secretx::path"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn uri_missing_param() {
        let u = SecretUri::parse("secretx:aws-sm:my-secret").unwrap();
        assert_eq!(u.param("field"), None);
    }

    #[test]
    fn uri_percent_decoded_path() {
        let u = SecretUri::parse("secretx:env:MY%20SECRET").unwrap();
        assert_eq!(u.path, "MY SECRET");
    }

    #[test]
    fn uri_percent_decoded_param_value() {
        let u = SecretUri::parse("secretx:aws-sm:my-secret?field=my%20field").unwrap();
        assert_eq!(u.param("field"), Some("my field"));
    }

    #[test]
    fn uri_percent_decoded_param_key() {
        let u = SecretUri::parse("secretx:aws-sm:my-secret?my%20key=val").unwrap();
        assert_eq!(u.param("my key"), Some("val"));
    }

    #[test]
    fn uri_invalid_percent_encoding() {
        assert!(matches!(
            SecretUri::parse("secretx:env:MY%ZZsecret"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn uri_incomplete_percent_encoding() {
        assert!(matches!(
            SecretUri::parse("secretx:env:MY%2"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn get_blocking_outside_runtime() {
        use std::sync::Arc;

        struct FakeStore;

        #[async_trait::async_trait]
        impl SecretStore for FakeStore {
            async fn get(&self) -> Result<SecretValue, SecretError> {
                Ok(SecretValue::new(b"test-value".to_vec()))
            }
            async fn refresh(&self) -> Result<SecretValue, SecretError> {
                self.get().await
            }
        }

        let store = Arc::new(FakeStore);
        let v = get_blocking(store.as_ref()).unwrap();
        assert_eq!(v.as_bytes(), b"test-value");
    }

    // Test the inside-runtime code path: get_blocking called from within an
    // existing tokio runtime must spawn a scoped thread rather than calling
    // block_on on the current executor thread (which would panic).
    // Oracle: the value returned must equal what FakeStore::get produces.
    #[cfg(feature = "blocking")]
    #[tokio::test]
    async fn get_blocking_inside_runtime() {
        use std::sync::Arc;

        struct FakeStore;

        #[async_trait::async_trait]
        impl SecretStore for FakeStore {
            async fn get(&self) -> Result<SecretValue, SecretError> {
                Ok(SecretValue::new(b"inside-runtime".to_vec()))
            }
            async fn refresh(&self) -> Result<SecretValue, SecretError> {
                self.get().await
            }
        }

        let store = Arc::new(FakeStore);
        // Calling get_blocking from inside a #[tokio::test] runtime exercises
        // the Ok(_) branch of Handle::try_current() — the scoped-thread path.
        let v = get_blocking(store.as_ref()).unwrap();
        assert_eq!(v.as_bytes(), b"inside-runtime");
    }

    // ── json_navigate / extract_path / extract_path_field tests ──────────────
    //
    // Oracle: expected output is derived by manual inspection of the literal
    // JSON, not by calling the code under test.

    #[test]
    fn navigate_empty_path_returns_input() {
        // An empty path must return the original bytes unchanged.
        let input = br#"{"k":"v"}"#;
        let result = json_navigate(input, &[]).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn navigate_single_key() {
        // Oracle: value of "data" is the sub-object {"key":"val"}.
        let input = br#"{"data":{"key":"val"}}"#;
        let result = json_navigate(input, &["data"]).unwrap();
        assert_eq!(result, br#"{"key":"val"}"#);
    }

    #[test]
    fn navigate_two_levels_vault_pattern() {
        // Vault KV v2 returns {"data":{"data":{...},"metadata":{...}}}.
        // Navigating ["data","data"] should return the inner secret object.
        let input = br#"{"data":{"data":{"password":"s3cr3t"},"metadata":{"version":3}}}"#;
        let result = json_navigate(input, &["data", "data"]).unwrap();
        assert_eq!(result, br#"{"password":"s3cr3t"}"#);
    }

    #[test]
    fn navigate_key_not_found() {
        let input = br#"{"a":"b"}"#;
        assert!(matches!(
            json_navigate(input, &["missing"]),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn navigate_intermediate_not_object() {
        // "data" is a string, not an object — navigating into it must fail.
        let input = br#"{"data":"flat-string"}"#;
        assert!(matches!(
            json_navigate(input, &["data", "key"]),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn navigate_key_with_escape_in_path() {
        // Key contains a JSON escape sequence; scan_string_key_b must decode it
        // to match the raw string supplied to json_navigate.
        // Oracle: the key `my\nkey` (backslash-n) decodes to a two-char string
        // "my" + newline + "key".  We navigate with the decoded form.
        let input = b"{\"my\\nkey\":\"found\"}";
        let result = json_navigate(input, &["my\nkey"]).unwrap();
        assert_eq!(result, b"\"found\"");
    }

    #[test]
    fn navigate_whitespace_around_value() {
        // Trailing whitespace on the returned slice must be trimmed.
        let input = br#"{"k":  42  }"#;
        let result = json_navigate(input, &["k"]).unwrap();
        assert_eq!(result, b"42");
    }

    #[test]
    fn navigate_empty_object_returns_not_found() {
        let input = br#"{}"#;
        assert!(matches!(
            json_navigate(input, &["k"]),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_path_vault_nested_object() {
        // extract_path(["data","data"]) should capture the inner object as bytes.
        let json = br#"{"data":{"data":{"token":"abc123"},"metadata":{}}}"#.to_vec();
        let sv = SecretValue::new(json);
        let inner = sv.extract_path(&["data", "data"]).unwrap();
        assert_eq!(inner.as_bytes(), br#"{"token":"abc123"}"#);
    }

    #[test]
    fn extract_path_field_vault_pattern() {
        // extract_path_field(["data","data"], "token") navigates to the inner
        // object and then extracts the string field "token".
        let json =
            br#"{"data":{"data":{"token":"s3cr3t","ttl":300},"metadata":{"version":1}}}"#.to_vec();
        let sv = SecretValue::new(json);
        let token = sv.extract_path_field(&["data", "data"], "token").unwrap();
        assert_eq!(token.as_bytes(), b"s3cr3t");
    }

    #[test]
    fn extract_path_missing_key_returns_decode_failed() {
        let json = br#"{"data":{"other":"val"}}"#.to_vec();
        let sv = SecretValue::new(json);
        assert!(matches!(
            sv.extract_path(&["data", "data"]),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    #[test]
    fn extract_path_field_missing_field_returns_decode_failed() {
        let json = br#"{"data":{"data":{"a":"b"}}}"#.to_vec();
        let sv = SecretValue::new(json);
        assert!(matches!(
            sv.extract_path_field(&["data", "data"], "missing"),
            Err(SecretError::DecodeFailed(_))
        ));
    }

    // ── skip_number_b direct tests ────────────────────────────────────────────
    //
    // These tests exercise skip_number_b via the byte-level json_find_value_b
    // path (extract_path). The existing skip_number_* tests exercise only the
    // char-based path (extract_field). Both paths must be tested independently.
    //
    // Oracle: RFC 8259 §6 defines the JSON number grammar. Malformed numbers
    // are identified by the grammar, not by the implementation under test.

    #[test]
    fn skip_number_b_bare_decimal_rejected_via_navigate() {
        // {"n":1.,"k":"v"} — skip_number_b must reject 1. (no fractional digits)
        // when scanning past the non-target field "n" to reach "k".
        // RFC 8259: decimal-point must be followed by one or more digits.
        let json = br#"{"n":1.,"k":"v"}"#.to_vec();
        let sv = SecretValue::new(json);
        assert!(
            matches!(sv.extract_path(&["k"]), Err(SecretError::DecodeFailed(_))),
            "bare decimal point must be rejected by skip_number_b"
        );
    }

    #[test]
    fn skip_number_b_bare_exponent_rejected_via_navigate() {
        // {"n":1e,"k":"v"} — skip_number_b must reject 1e (no exponent digits).
        // RFC 8259: exponent marker must be followed by one or more digits.
        let json = br#"{"n":1e,"k":"v"}"#.to_vec();
        let sv = SecretValue::new(json);
        assert!(
            matches!(sv.extract_path(&["k"]), Err(SecretError::DecodeFailed(_))),
            "bare exponent must be rejected by skip_number_b"
        );
    }

    #[test]
    fn skip_number_b_signed_exponent_no_digits_rejected_via_navigate() {
        // {"n":1e+,"k":"v"} — exponent sign must be followed by digits.
        let json = br#"{"n":1e+,"k":"v"}"#.to_vec();
        let sv = SecretValue::new(json);
        assert!(
            matches!(sv.extract_path(&["k"]), Err(SecretError::DecodeFailed(_))),
            "signed exponent with no digits must be rejected by skip_number_b"
        );
    }

    #[test]
    fn skip_number_b_valid_number_allows_navigation() {
        // Sanity: a well-formed number in a non-target field must not block navigation.
        let json = br#"{"n":3.14e2,"k":"found"}"#.to_vec();
        let sv = SecretValue::new(json);
        let result = sv.extract_path(&["k"]).unwrap();
        assert_eq!(result.as_bytes(), b"\"found\"");
    }

    // RFC 8259 §6: a non-zero integer part must not have leading zeros.
    // Oracle: RFC 8259 §6 grammar — int = zero / (digit1-9 *DIGIT).
    // These mirror skip_number_leading_zero_* but exercise the byte-level
    // skip_number_b path (via extract_path / json_find_value_b).

    #[test]
    fn skip_number_b_leading_zero_rejected_via_navigate() {
        // 01 — leading zero in non-target field, invalid per RFC 8259.
        let json = br#"{"n":01,"k":"v"}"#.to_vec();
        let sv = SecretValue::new(json);
        assert!(
            matches!(sv.extract_path(&["k"]), Err(SecretError::DecodeFailed(_))),
            "leading zero must be rejected by skip_number_b"
        );
    }

    #[test]
    fn skip_number_b_negative_leading_zero_rejected_via_navigate() {
        // -01 — leading zero after minus, invalid per RFC 8259.
        let json = br#"{"n":-01,"k":"v"}"#.to_vec();
        let sv = SecretValue::new(json);
        assert!(
            matches!(sv.extract_path(&["k"]), Err(SecretError::DecodeFailed(_))),
            "-01 must be rejected by skip_number_b"
        );
    }

    #[test]
    fn skip_number_b_zero_alone_accepted_via_navigate() {
        // Bare 0 is valid per RFC 8259 (zero = %x30).
        let json = br#"{"n":0,"k":"v"}"#.to_vec();
        let sv = SecretValue::new(json);
        let result = sv.extract_path(&["k"]).unwrap();
        assert_eq!(result.as_bytes(), b"\"v\"");
    }

    // RFC 8259 §7: U+0000–U+001F must be escaped; skip_string_b must reject
    // bare control characters in skipped string values, consistent with
    // json_skip_string (char path).
    // Oracle: RFC 8259 §7 grammar — unescaped = %x20-21 / %x23-5B / %x5D-10FFFF.

    #[test]
    fn skip_string_b_control_char_in_skipped_value_rejected_via_navigate() {
        // U+0001 (SOH) in a non-target string value must cause DecodeFailed
        // even though the target field "k" is valid.
        let json = b"{\"other\":\"\x01bad\",\"k\":\"v\"}".to_vec();
        let sv = SecretValue::new(json);
        assert!(
            matches!(sv.extract_path(&["k"]), Err(SecretError::DecodeFailed(_))),
            "control char in skipped string value must be rejected by skip_string_b"
        );
    }

    #[test]
    fn skip_string_b_null_byte_in_skipped_value_rejected_via_navigate() {
        // U+0000 (NUL) in a non-target string value must also be rejected.
        let json = b"{\"other\":\"val\x00ue\",\"k\":\"v\"}".to_vec();
        let sv = SecretValue::new(json);
        assert!(
            matches!(sv.extract_path(&["k"]), Err(SecretError::DecodeFailed(_))),
            "NUL byte in skipped string value must be rejected by skip_string_b"
        );
    }

    #[test]
    fn skip_string_b_space_in_skipped_value_accepted_via_navigate() {
        // U+0020 (SPACE) is the first non-control char; must pass through.
        let json = br#"{"other":"abc def","k":"v"}"#.to_vec();
        let sv = SecretValue::new(json);
        let result = sv.extract_path(&["k"]).unwrap();
        assert_eq!(result.as_bytes(), b"\"v\"");
    }

    // ── WritableSecretStore tests ────────────────────────────────────────────

    // A minimal concrete type that implements both SecretStore and
    // WritableSecretStore for use in the tests below.
    struct FakeWritable {
        value: std::sync::Mutex<Vec<u8>>,
    }

    impl FakeWritable {
        fn new(initial: &[u8]) -> Self {
            Self {
                value: std::sync::Mutex::new(initial.to_vec()),
            }
        }
    }

    #[async_trait::async_trait]
    impl SecretStore for FakeWritable {
        async fn get(&self) -> Result<SecretValue, SecretError> {
            let bytes = self.value.lock().unwrap().clone();
            Ok(SecretValue::new(bytes))
        }
        async fn refresh(&self) -> Result<SecretValue, SecretError> {
            self.get().await
        }
    }

    #[async_trait::async_trait]
    impl WritableSecretStore for FakeWritable {
        async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
            *self.value.lock().unwrap() = value.as_bytes().to_vec();
            Ok(())
        }
    }

    // A read-only store used to verify SecretStore impls need not have put.
    struct ReadOnlyStore;

    #[async_trait::async_trait]
    impl SecretStore for ReadOnlyStore {
        async fn get(&self) -> Result<SecretValue, SecretError> {
            Ok(SecretValue::new(b"read-only".to_vec()))
        }
        async fn refresh(&self) -> Result<SecretValue, SecretError> {
            self.get().await
        }
    }

    // Helper used by the compile-time Send+Sync assertion test.
    fn assert_send_sync<T: Send + Sync>() {}

    #[tokio::test]
    async fn writable_store_put_returns_ok() {
        // Oracle: put on a concrete FakeWritable must return Ok(()).
        let store = FakeWritable::new(b"initial");
        let result = store.put(SecretValue::new(b"new-value".to_vec())).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn writable_store_put_then_get_round_trip() {
        // Oracle: after put, get must return the same bytes.
        let store = FakeWritable::new(b"old");
        store
            .put(SecretValue::new(b"round-trip-value".to_vec()))
            .await
            .unwrap();
        let got = store.get().await.unwrap();
        assert_eq!(got.as_bytes(), b"round-trip-value");
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn get_blocking_with_dyn_writable_store() {
        use std::sync::Arc;
        // Oracle: get_blocking must work when the concrete type is
        // Arc<dyn WritableSecretStore>, because WritableSecretStore: SecretStore.
        let store: Arc<dyn WritableSecretStore> = Arc::new(FakeWritable::new(b"via-writable-dyn"));
        let v = get_blocking(store.as_ref()).unwrap();
        assert_eq!(v.as_bytes(), b"via-writable-dyn");
    }

    #[cfg(feature = "blocking")]
    #[tokio::test]
    async fn get_blocking_with_dyn_writable_store_inside_runtime() {
        use std::sync::Arc;
        // Oracle: same as above but exercising the inside-runtime scoped-thread path.
        let store: Arc<dyn WritableSecretStore> = Arc::new(FakeWritable::new(b"via-writable-dyn"));
        let v = get_blocking(store.as_ref()).unwrap();
        assert_eq!(v.as_bytes(), b"via-writable-dyn");
    }

    #[test]
    fn writable_store_is_send_sync() {
        // Compile-time check: FakeWritable must satisfy Send + Sync.
        assert_send_sync::<FakeWritable>();
    }

    #[tokio::test]
    async fn writable_store_get_and_refresh_accessible_via_secret_store_supertrait() {
        // Oracle: calling get() and refresh() through &dyn WritableSecretStore
        // must dispatch to FakeWritable's SecretStore impl.
        let store: &dyn WritableSecretStore = &FakeWritable::new(b"supertrait-value");
        let got = store.get().await.unwrap();
        assert_eq!(got.as_bytes(), b"supertrait-value");
        let refreshed = store.refresh().await.unwrap();
        assert_eq!(refreshed.as_bytes(), b"supertrait-value");
    }

    #[tokio::test]
    async fn secret_store_without_put_still_compiles() {
        // Oracle: a type that only implements SecretStore (no WritableSecretStore)
        // must still be usable as a SecretStore — put is not required.
        let store = ReadOnlyStore;
        let got = store.get().await.unwrap();
        assert_eq!(got.as_bytes(), b"read-only");
    }
}
