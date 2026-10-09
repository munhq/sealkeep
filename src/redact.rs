//! Redaction of secret values from a byte stream.
//!
//! A command that gets a secret in its environment can print it: `env`, a debug log, an
//! error that echoes a request. The agent reads that output, so each value is replaced
//! before the output leaves sealkeep. A value is also matched in the encoded forms that
//! tools commonly print: JSON-escaped, percent-encoded and base64.
//!
//! The stream comes in chunks, and a value can cross a chunk boundary. The redactor
//! holds back the last `longest pattern - 1` bytes of each chunk, so a match that starts
//! in one chunk and ends in the next is still found.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// Values shorter than this are not redacted: a 1-3 byte pattern would replace common
/// text in the output, and such a value is not a credential.
pub const MIN_REDACT_LEN: usize = 4;

/// A value this long is redacted whatever its key is.
const ALWAYS_REDACT_LEN: usize = 16;

const SECRET_WORDS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASS",
    "PWD",
    "DSN",
    "PRIVATE",
    "CREDENTIAL",
    "AUTH",
    "SALT",
    "COOKIE",
    "SESSION",
    "WEBHOOK",
    "SIGNING",
    "MNEMONIC",
    "SEED",
    "CERT",
    "BEARER",
];

/// Whether a key names a secret.
pub fn secret_key_name(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    SECRET_WORDS.iter().any(|w| k.contains(w))
}

/// `scheme://user:password@host`
pub fn url_with_password(value: &str) -> bool {
    value
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('@'))
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
}

/// Whether a value is redacted. A config value such as `PORT=3000` or
/// `NODE_ENV=production` stays readable in the output.
pub fn should_redact(name: &str, value: &str) -> bool {
    let key = crate::names::key_of(name);
    value.len() >= MIN_REDACT_LEN
        && (secret_key_name(key) || url_with_password(value) || value.len() >= ALWAYS_REDACT_LEN)
}

#[derive(Debug, Clone)]
pub struct Redactor {
    ac: Option<AhoCorasick>,
    labels: Vec<Vec<u8>>,
    holdback: usize,
}

impl Redactor {
    /// `secrets` is `(name, value)`. Names label the replacement, values are matched.
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut labels: Vec<Vec<u8>> = Vec::new();
        for (name, value) in secrets {
            if !should_redact(name, value) {
                continue;
            }
            let label = format!("[sealkeep:{name}]").into_bytes();
            for form in forms(value) {
                if !patterns.contains(&form) {
                    patterns.push(form);
                    labels.push(label.clone());
                }
            }
        }
        if patterns.is_empty() {
            return Self {
                ac: None,
                labels,
                holdback: 0,
            };
        }
        let longest = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("literal patterns always build");
        Self {
            ac: Some(ac),
            labels,
            holdback: longest.saturating_sub(1),
        }
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.ac.is_none()
    }

    /// Redact a complete buffer.
    pub fn redact_all(&self, input: &[u8]) -> Vec<u8> {
        let mut s = self.stream();
        let mut out = s.push(input);
        out.extend(s.finish());
        out
    }

    pub fn redact_str(&self, input: &str) -> String {
        String::from_utf8_lossy(&self.redact_all(input.as_bytes())).into_owned()
    }

    pub fn stream(&self) -> RedactStream<'_> {
        RedactStream {
            r: self,
            pending: Vec::new(),
        }
    }
}

/// The forms of one value that are matched.
fn forms(value: &str) -> Vec<Vec<u8>> {
    let mut out = vec![value.as_bytes().to_vec()];
    let json = serde_json::to_string(value).unwrap_or_default();
    let json = json.trim_matches('"');
    if json != value {
        out.push(json.as_bytes().to_vec());
    }
    let pct = percent_encode(value);
    if pct != value {
        out.push(pct.into_bytes());
    }
    out.push(STANDARD.encode(value).into_bytes());
    out.push(URL_SAFE_NO_PAD.encode(value).into_bytes());
    out.retain(|f| f.len() >= MIN_REDACT_LEN);
    out
}

/// RFC 3986 percent-encoding of everything outside the unreserved set.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub struct RedactStream<'a> {
    r: &'a Redactor,
    pending: Vec<u8>,
}

impl RedactStream<'_> {
    /// Add a chunk. Returns the bytes that are safe to write now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.r.ac else {
            return chunk.to_vec();
        };
        self.pending.extend_from_slice(chunk);
        // A match that starts before `safe` is complete in the buffer: a longer
        // pattern that starts there would need more than `holdback` bytes after it.
        let safe = self.pending.len().saturating_sub(self.r.holdback);
        let mut out = Vec::with_capacity(self.pending.len());
        let mut cursor = 0;
        for m in ac.find_iter(&self.pending) {
            if m.start() >= safe {
                break;
            }
            out.extend_from_slice(&self.pending[cursor..m.start()]);
            out.extend_from_slice(&self.r.labels[m.pattern().as_usize()]);
            cursor = m.end();
        }
        let emit_to = cursor.max(safe);
        out.extend_from_slice(&self.pending[cursor..emit_to]);
        self.pending.drain(..emit_to);
        out
    }

    /// The end of the stream. Returns the rest.
    pub fn finish(&mut self) -> Vec<u8> {
        let rest = std::mem::take(&mut self.pending);
        let Some(ac) = &self.r.ac else {
            return rest;
        };
        let mut out = Vec::with_capacity(rest.len());
        let mut cursor = 0;
        for m in ac.find_iter(&rest) {
            out.extend_from_slice(&rest[cursor..m.start()]);
            out.extend_from_slice(&self.r.labels[m.pattern().as_usize()]);
            cursor = m.end();
        }
        out.extend_from_slice(&rest[cursor..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new([("API_KEY", "sk-live-abc123"), ("PASS", "p@ss w\"rd")])
    }

    #[test]
    fn raw_and_encoded_forms() {
        let r = r();
        assert_eq!(
            r.redact_str("key=sk-live-abc123 end"),
            "key=[sealkeep:API_KEY] end"
        );
        assert_eq!(r.redact_str("q=p%40ss%20w%22rd"), "q=[sealkeep:PASS]");
        assert_eq!(
            r.redact_str(r#"{"p":"p@ss w\"rd"}"#),
            r#"{"p":"[sealkeep:PASS]"}"#
        );
        let b64 = STANDARD.encode("sk-live-abc123");
        assert_eq!(
            r.redact_str(&format!("x {b64} y")),
            "x [sealkeep:API_KEY] y"
        );
    }

    #[test]
    fn match_across_every_chunk_boundary() {
        let r = r();
        let text = b"start sk-live-abc123 middle sk-live-abc123 end";
        let want = b"start [sealkeep:API_KEY] middle [sealkeep:API_KEY] end".to_vec();
        for size in 1..text.len() {
            let mut s = r.stream();
            let mut out = Vec::new();
            for chunk in text.chunks(size) {
                out.extend(s.push(chunk));
            }
            out.extend(s.finish());
            assert_eq!(out, want, "chunk size {size}");
        }
    }

    #[test]
    fn config_values_stay_readable() {
        let r = Redactor::new([
            ("app/dev/PORT", "3000"),
            ("app/dev/NODE_ENV", "production"),
            ("app/dev/DATABASE_URL", "postgres://u:pw@h/db"),
            ("app/dev/SIGNER", "0123456789abcdef0123"),
        ]);
        assert_eq!(
            r.redact_str("3000 production postgres://u:pw@h/db 0123456789abcdef0123"),
            "3000 production [sealkeep:app/dev/DATABASE_URL] [sealkeep:app/dev/SIGNER]"
        );
    }

    #[test]
    fn short_values_pass_through() {
        let r = Redactor::new([("PIN", "123")]);
        assert!(r.is_empty());
        assert_eq!(r.redact_str("123"), "123");
    }

    #[test]
    fn longest_match_wins() {
        let r = Redactor::new([("A_KEY", "abcd"), ("B_KEY", "abcdefgh")]);
        assert_eq!(
            r.redact_str("abcdefgh abcd"),
            "[sealkeep:B_KEY] [sealkeep:A_KEY]"
        );
    }
}
