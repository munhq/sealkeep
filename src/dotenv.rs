//! A dotenv parser whose errors hold a line number and never the text of the line.
//!
//! The parser of the `dotenvy` crate puts the whole line into its error. `scan` printed
//! such an error, and with it the password on that line. Here a line that does not
//! parse is skipped and reported by its number, and the next lines are still read.
//!
//! Supported: `KEY=value`, `export KEY=value`, spaces around `=`, `# comments`, a ` #`
//! comment after an unquoted value, single quotes (literal), double quotes (with `\n`,
//! `\r`, `\t`, `\"`, `\\` escapes), and quoted values over more than one line.

use anyhow::{Context, Result};
use std::path::Path;

#[derive(Debug, Default)]
pub struct Parsed {
    pub entries: Vec<(String, String)>,
    /// The 1-based numbers of the lines that do not parse.
    pub bad_lines: Vec<usize>,
}

fn valid_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

pub fn parse(text: &str) -> Parsed {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Parsed::default();
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let line = lines[i].trim_start();
        i += 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, rest)) = line.split_once('=') else {
            out.bad_lines.push(start + 1);
            continue;
        };
        let key = k.trim();
        if !valid_key(key) {
            out.bad_lines.push(start + 1);
            continue;
        }
        let rest = rest.trim_start();
        let value = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => {
                // The value ends at the next unescaped quote, on this line or a later one.
                let mut buf = rest[1..].to_string();
                let mut found = None;
                loop {
                    if let Some(end) = closing_quote(&buf, q) {
                        found = Some(end);
                        break;
                    }
                    if i >= lines.len() {
                        break;
                    }
                    buf.push('\n');
                    buf.push_str(lines[i]);
                    i += 1;
                }
                match found {
                    Some(end) => {
                        let raw = &buf[..end];
                        if q == '"' {
                            unescape(raw)
                        } else {
                            raw.to_string()
                        }
                    }
                    None => {
                        // No closing quote: report this line, and read the lines after it.
                        out.bad_lines.push(start + 1);
                        i = start + 1;
                        continue;
                    }
                }
            }
            _ => match rest.find(" #") {
                Some(p) => rest[..p].trim_end().to_string(),
                None => rest.trim_end().to_string(),
            },
        };
        out.entries.push((key.to_string(), value));
    }
    out
}

fn closing_quote(s: &str, q: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if q == '"' && c == '\\' && !escaped {
            escaped = true;
            continue;
        }
        if c == q && !escaped {
            return Some(i);
        }
        escaped = false;
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(o) => out.push(o),
            None => out.push('\\'),
        }
    }
    out
}

pub fn parse_file(path: &Path) -> Result<Parsed> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(parse(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms() {
        let p = parse(
            "# c\nA=1\nexport B = two words # note\nC='lit $x \\n'\nD=\"a\\nb \\\"q\\\"\"\nE=\"line1\nline2\"\n\nF=\n",
        );
        assert!(p.bad_lines.is_empty(), "{:?}", p.bad_lines);
        let get = |k: &str| p.entries.iter().find(|(a, _)| a == k).unwrap().1.clone();
        assert_eq!(get("A"), "1");
        assert_eq!(get("B"), "two words");
        assert_eq!(get("C"), "lit $x \\n");
        assert_eq!(get("D"), "a\nb \"q\"");
        assert_eq!(get("E"), "line1\nline2");
        assert_eq!(get("F"), "");
    }

    #[test]
    fn a_bad_line_is_skipped_and_its_text_is_not_kept() {
        let p = parse("A=1\nuser@example.com=hunter2-secret\nnot a pair\nB=2\nC=\"open\nD=4\n");
        assert_eq!(p.bad_lines, vec![2, 3, 5]);
        assert_eq!(p.entries.len(), 3);
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("hunter2"));
    }
}
