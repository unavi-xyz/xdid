use std::{
    fmt::Display,
    str::FromStr,
};

use serde::{
    Deserialize,
    Serialize,
};
use smol_str::SmolStr;

use super::ParseError;
use crate::uri::{
    Segment,
    is_query_or_fragment,
    is_segment,
};

/// Fields are private; see [`super::DidUrl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativeDidUrl {
    path:     RelativeDidUrlPath,
    /// [DID query](https://www.w3.org/TR/did-core/#query) ([RFC 3986 - 3.4. Query](https://www.rfc-editor.org/rfc/rfc3986#section-3.4))
    query:    Option<SmolStr>,
    /// [DID fragment](https://www.w3.org/TR/did-core/#fragment) ([RFC 3986 - 3.5. Fragment](https://www.rfc-editor.org/rfc/rfc3986#section-3.5))
    fragment: Option<SmolStr>,
}

impl RelativeDidUrl {
    /// Builds a [`RelativeDidUrl`] from its components.
    ///
    /// # Errors
    ///
    /// Returns an error if any component does not conform to
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986).
    pub fn new(
        path: RelativeDidUrlPath,
        query: Option<SmolStr>,
        fragment: Option<SmolStr>,
    ) -> Result<Self, ParseError> {
        // The variants are public, so the contents may disagree with the
        // variant.
        if RelativeDidUrlPath::from_str(path.as_str())? != path {
            return Err(ParseError::PathVariantMismatch);
        }

        if [query.as_deref(), fragment.as_deref()]
            .into_iter()
            .flatten()
            .any(|v| !is_query_or_fragment(v))
        {
            return Err(ParseError::Query);
        }

        Ok(Self {
            path,
            query,
            fragment,
        })
    }

    /// Builds from components already known to be valid.
    pub(super) const fn from_parts(
        path: RelativeDidUrlPath,
        query: Option<SmolStr>,
        fragment: Option<SmolStr>,
    ) -> Self {
        Self {
            path,
            query,
            fragment,
        }
    }

    #[must_use]
    pub const fn path(&self) -> &RelativeDidUrlPath {
        &self.path
    }

    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }
}

impl Display for RelativeDidUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self.path.to_string();
        let query = self
            .query
            .as_ref()
            .map_or_else(String::new, |q| format!("?{q}"));
        let fragment = self
            .fragment
            .as_ref()
            .map_or_else(String::new, |f| format!("#{f}"));
        f.write_fmt(format_args!("{path}{query}{fragment}"))
    }
}

impl FromStr for RelativeDidUrl {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Fragment first: a fragment may itself contain "?".
        let (rest, fragment) = match s.split_once('#') {
            Some((rest, fragment)) => (rest, Some(fragment)),
            None => (s, None),
        };

        let (path, query) = match rest.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (rest, None),
        };

        if [query, fragment]
            .into_iter()
            .flatten()
            .any(|v| !is_query_or_fragment(v))
        {
            return Err(ParseError::Query);
        }

        Ok(Self {
            path:     RelativeDidUrlPath::from_str(path)?,
            query:    query.map(Into::into),
            fragment: fragment.map(Into::into),
        })
    }
}

impl Serialize for RelativeDidUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v = self.to_string();
        serializer.serialize_str(&v)
    }
}

impl<'de> Deserialize<'de> for RelativeDidUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s)
            .map_err(|e| serde::de::Error::custom(format!("invalid relative DID URL: {e}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelativeDidUrlPath {
    /// Absolute-path reference. `path-absolute` from [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3.3)
    Absolute(String),
    /// Relative-path reference. `path-noscheme` from [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3.3)
    NoScheme(String),
    /// Empty path. `path-empty` from [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3.3)
    Empty,
}

impl RelativeDidUrlPath {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Absolute(s) | Self::NoScheme(s) => s,
            Self::Empty => "",
        }
    }
}

impl Display for RelativeDidUrlPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RelativeDidUrlPath {
    type Err = ParseError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        if path.is_empty() {
            return Ok(Self::Empty);
        }
        if path.starts_with('/') {
            // path-absolute = "/" [ segment-nz *( "/" segment ) ]
            if path.starts_with("//") {
                return Err(ParseError::PathDoubleSlash);
            }

            if !path
                .split('/')
                .skip(1)
                .all(|v| is_segment(v, Segment::Base))
            {
                return Err(ParseError::PathSegment);
            }

            Ok(Self::Absolute(path.to_string()))
        } else {
            // path-noscheme = segment-nz-nc *( "/" segment )
            if !path.split('/').all(|v| is_segment(v, Segment::NzNc)) {
                return Err(ParseError::PathSegment);
            }

            Ok(Self::NoScheme(path.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_before_query() {
        let url = RelativeDidUrl::from_str("foo#bar?baz").expect("valid");

        assert_eq!(url.path, RelativeDidUrlPath::NoScheme("foo".to_string()));
        assert_eq!(url.query, None);
        assert_eq!(url.fragment.as_deref(), Some("bar?baz"));
        assert_eq!(url.to_string(), "foo#bar?baz");
    }

    #[test]
    fn test_round_trip() {
        for s in ["", "#key1", "/a/b?q=1#f", "foo/bar", "?q=1", "/abs"] {
            let url = RelativeDidUrl::from_str(s).expect("valid");
            assert_eq!(url.to_string(), s);
        }
    }

    #[test]
    fn test_rejects_control_characters() {
        for s in [
            "#frag with space",
            "?a=b\r\nX-Evil: 1",
            "/path%4",
            "#\u{430}",
        ] {
            assert!(
                RelativeDidUrl::from_str(s).is_err(),
                "{s:?} should be rejected"
            );
        }
    }

    #[test]
    fn test_rejects_double_slash() {
        assert!(RelativeDidUrl::from_str("//evil.com/path").is_err());
    }
}
