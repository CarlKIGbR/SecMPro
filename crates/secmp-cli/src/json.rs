// SPDX-License-Identifier: AGPL-3.0-or-later
//! The JSON-lines writer (OPEN-M7-11 A): one object per line, the first key `type`, hand-written, RFC 8259 escaping.
//! The keys are fixed names of this program; only the values carry text from outside (a contact's name, a message), and
//! those are escaped: no value can end the line or the string early.

use core::fmt::Write as _;

/// A JSON string literal of `s`: quoted, with `"`, `\` and every control character below U+0020 escaped (RFC 8259 §7).
#[must_use]
pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A JSON array of already rendered values.
#[must_use]
pub fn list(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

/// An object under construction: `type` first, then the fields in the order they are added.
pub struct Obj(String);

impl Obj {
    /// An object of the given `type`.
    #[must_use]
    pub fn new(kind: &'static str) -> Self {
        Self(format!("{{\"type\":{}", string(kind)))
    }

    /// A text field.
    #[must_use]
    pub fn text(mut self, key: &'static str, value: &str) -> Self {
        let _ = write!(self.0, ",{}:{}", string(key), string(value));
        self
    }

    /// A number field.
    #[must_use]
    pub fn num(mut self, key: &'static str, value: u64) -> Self {
        let _ = write!(self.0, ",{}:{value}", string(key));
        self
    }

    /// A field whose value is already rendered JSON ([`list`], [`Obj::done`]).
    #[must_use]
    pub fn raw(mut self, key: &'static str, value: &str) -> Self {
        let _ = write!(self.0, ",{}:{value}", string(key));
        self
    }

    /// The object as text.
    #[must_use]
    pub fn done(mut self) -> String {
        self.0.push('}');
        self.0
    }
}

/// `bytes` as lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8259 §7: the quote, the backslash and every control character are escaped; everything else (also non-ASCII and
    /// U+007F) is written as it is.
    #[test]
    fn strings_are_escaped() {
        assert_eq!(string("plain"), "\"plain\"");
        assert_eq!(string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(string("l1\nl2\r\t"), "\"l1\\nl2\\r\\t\"");
        assert_eq!(string("\u{0}\u{1f}\u{8}\u{c}"), "\"\\u0000\\u001f\\b\\f\"");
        assert_eq!(string("é\u{7f}\u{1f642}"), "\"é\u{7f}\u{1f642}\"");
        assert!(
            !string("x\ny").contains('\n'),
            "a value never ends the line"
        );
    }

    #[test]
    fn objects_keep_type_first_and_the_order_of_fields() {
        let line = Obj::new("contact")
            .num("id", 3)
            .text("state", "unverified")
            .raw("list", &list(&["1".to_owned(), string("a")]))
            .done();
        assert_eq!(
            line,
            "{\"type\":\"contact\",\"id\":3,\"state\":\"unverified\",\"list\":[1,\"a\"]}"
        );
        assert_eq!(Obj::new("closed").done(), "{\"type\":\"closed\"}");
        assert_eq!(hex(&[0, 0xab, 0xff]), "00abff");
    }
}
