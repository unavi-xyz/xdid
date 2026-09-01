#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Segment {
    /// segment
    Base,
    /// segment-nz-nc
    NzNc,
}

/// Whether the string conforms to a given [Segment], following [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
pub fn is_segment(value: &str, segment: Segment) -> bool {
    if segment == Segment::NzNc && value.is_empty() {
        return false;
    }

    // pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
    // segment-nz-nc excludes ":".
    scan(value, |b| {
        is_unreserved(b) || is_sub_delim(b) || b == b'@' || (b == b':' && segment != Segment::NzNc)
    })
}

/// Whether the string conforms to `query` / `fragment` from [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.4),
/// which share the production `*( pchar / "/" / "?" )`.
pub fn is_query_or_fragment(value: &str) -> bool {
    scan(value, |b| {
        is_unreserved(b) || is_sub_delim(b) || matches!(b, b':' | b'@' | b'/' | b'?')
    })
}

/// Whether the string conforms to `*idchar` from the [DID syntax](https://www.w3.org/TR/did-core/#did-syntax).
pub fn is_idchars(value: &str) -> bool {
    scan(value, |b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
    })
}

/// Scans bytes rather than chars: every production here is ASCII-only, and a
/// multi-byte character can never satisfy `allowed`.
fn scan(value: &str, allowed: impl Fn(u8) -> bool) -> bool {
    let mut bytes = value.bytes();

    while let Some(b) = bytes.next() {
        if b == b'%' {
            // pct-encoded = "%" HEXDIG HEXDIG
            let (Some(high), Some(low)) = (bytes.next(), bytes.next()) else {
                return false;
            };

            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return false;
            }
        } else if !allowed(b) {
            return false;
        }
    }

    true
}

/// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
const fn is_sub_delim(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_length() {
        assert!(is_segment("", Segment::Base));
        assert!(!is_segment("", Segment::NzNc));
    }

    #[test]
    fn test_segment_alphanumeric() {
        assert!(is_segment(
            "abcdefghijklmnopqrstuvwxyz0123456789",
            Segment::Base
        ));
    }

    #[test]
    fn test_segment_symbols() {
        assert!(is_segment("!$&'()*+,;=@", Segment::Base));
        assert!(is_segment("!$&'()*+,;=@", Segment::NzNc));
    }

    #[test]
    fn test_segment_colon() {
        assert!(is_segment(":", Segment::Base));
        assert!(!is_segment(":", Segment::NzNc));
    }

    #[test]
    fn test_segment_pct_encode() {
        assert!(is_segment("%30%f9a", Segment::Base));
        assert!(!is_segment("%3%f9a", Segment::Base));
        assert!(!is_segment("%%f9a", Segment::Base));
    }

    #[test]
    fn test_truncated_pct_encode() {
        assert!(!is_segment("%", Segment::Base));
        assert!(!is_segment("%4", Segment::Base));
        assert!(!is_segment("abc%", Segment::Base));
        assert!(!is_segment("abc%4", Segment::Base));
        assert!(!is_segment("%4g", Segment::Base));
        assert!(!is_query_or_fragment("abc%4"));
        assert!(!is_idchars("abc%"));
    }

    #[test]
    fn test_rejects_non_ascii() {
        // ALPHA and DIGIT are ASCII-only; homographs must not pass as
        // unreserved.
        assert!(!is_segment("p\u{430}th", Segment::Base));
        assert!(!is_segment("日本", Segment::Base));
        assert!(!is_segment("\u{2177}", Segment::Base));
        assert!(!is_query_or_fragment("k\u{435}y=1"));
        assert!(!is_idchars("\u{430}bc"));
    }

    #[test]
    fn test_query_or_fragment() {
        assert!(is_query_or_fragment(""));
        assert!(is_query_or_fragment("a=1&b=2"));
        assert!(is_query_or_fragment("service=x&relativeRef=/records/abc"));
        assert!(is_query_or_fragment("frag?with?question"));
        assert!(!is_query_or_fragment("a=b\r\nX-Evil: 1"));
        assert!(!is_query_or_fragment("has space"));
        assert!(!is_query_or_fragment("trailing\n"));
        assert!(!is_query_or_fragment("nul\0byte"));
    }

    #[test]
    fn test_idchars() {
        assert!(is_idchars(""));
        assert!(is_idchars("abc123.-_"));
        assert!(is_idchars("%3A"));
        assert!(!is_idchars("%zz"));
        assert!(!is_idchars("~"));
        assert!(!is_idchars("a:b"));
        assert!(!is_idchars("a/b"));
    }
}
