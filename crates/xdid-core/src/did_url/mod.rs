use std::{
    fmt::Display,
    str::FromStr,
};

use serde::{
    Deserialize,
    Serialize,
};
use smol_str::SmolStr;
use thiserror::Error;

use crate::{
    did::Did,
    did_url::relative::{
        RelativeDidUrl,
        RelativeDidUrlPath,
    },
    uri::{
        Segment,
        is_query_or_fragment,
        is_segment,
    },
};

pub mod relative;

/// Why a string is not a [`DidUrl`] or a [`relative::RelativeDidUrl`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error(transparent)]
    Did(#[from] crate::did::ParseError),
    #[error("path does not start with `/`")]
    PathNotAbsolute,
    #[error("path begins with `//`, which would read as an authority")]
    PathDoubleSlash,
    #[error("invalid path segment")]
    PathSegment,
    #[error("path does not match its variant")]
    PathVariantMismatch,
    #[error("invalid query")]
    Query,
    #[error("invalid fragment")]
    Fragment,
}

/// Fields are private so that every value has been through the RFC 3986
/// grammar; callers may otherwise smuggle control characters into a type whose
/// whole purpose is to assert well-formedness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidUrl {
    did:          Did,
    /// [DID path](https://www.w3.org/TR/did-core/#path). `path-abempty` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    path_abempty: Option<String>,
    /// [DID query](https://www.w3.org/TR/did-core/#query). `query` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    query:        Option<SmolStr>,
    /// [DID fragment](https://www.w3.org/TR/did-core/#fragment). `fragment` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    fragment:     Option<SmolStr>,
}

impl Serialize for DidUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v = self.to_string();
        serializer.serialize_str(&v)
    }
}

impl<'de> Deserialize<'de> for DidUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|e| serde::de::Error::custom(format!("invalid DID URL: {e}")))
    }
}

impl DidUrl {
    /// Builds a [`DidUrl`] from its components.
    ///
    /// # Errors
    ///
    /// Returns an error if any component does not conform to
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986).
    pub fn new(
        did: Did,
        path_abempty: Option<String>,
        query: Option<SmolStr>,
        fragment: Option<SmolStr>,
    ) -> Result<Self, ParseError> {
        if let Some(path) = path_abempty.as_deref() {
            validate_path_abempty(path)?;
        }

        if [query.as_deref(), fragment.as_deref()]
            .into_iter()
            .flatten()
            .any(|v| !is_query_or_fragment(v))
        {
            return Err(ParseError::Query);
        }

        Ok(Self {
            did,
            path_abempty,
            query,
            fragment,
        })
    }

    #[must_use]
    pub const fn did(&self) -> &Did {
        &self.did
    }

    #[must_use]
    pub fn path_abempty(&self) -> Option<&str> {
        self.path_abempty.as_deref()
    }

    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    #[must_use]
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// Attempts to convert the [`DidUrl`] into a [`RelativeDidUrl`].
    #[must_use]
    pub fn to_relative(&self) -> Option<RelativeDidUrl> {
        let path =
            RelativeDidUrlPath::from_str(self.path_abempty.as_deref().unwrap_or_default()).ok()?;

        Some(RelativeDidUrl::from_parts(
            path,
            self.query.clone(),
            self.fragment.clone(),
        ))
    }

    /// Whether this URL, viewed relative to its own DID, is `other`.
    ///
    /// Equivalent to comparing against [`Self::to_relative`], without building
    /// one per comparison.
    #[must_use]
    pub fn matches_relative(&self, other: &RelativeDidUrl) -> bool {
        self.path_abempty.as_deref().unwrap_or_default() == other.path().as_str()
            && self.query.as_deref() == other.query()
            && self.fragment.as_deref() == other.fragment()
    }
}

fn validate_path_abempty(path: &str) -> Result<(), ParseError> {
    // path-abempty = *( "/" segment )
    if !path.starts_with('/') {
        return Err(ParseError::PathNotAbsolute);
    }

    if !path
        .split('/')
        .skip(1)
        .all(|v| is_segment(v, Segment::Base))
    {
        return Err(ParseError::PathSegment);
    }

    Ok(())
}

impl Display for DidUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut url = self.did.to_string();

        if let Some(ref path) = self.path_abempty {
            url.push_str(path);
        }

        if let Some(ref query) = self.query {
            url.push('?');
            url.push_str(query);
        }

        if let Some(ref fragment) = self.fragment {
            url.push('#');
            url.push_str(fragment);
        }

        f.write_str(&url)
    }
}

impl FromStr for DidUrl {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (did_str, mut rest) = s.split_at(s.find(['/', '?', '#']).unwrap_or(s.len()));

        let did = Did::from_str(did_str)?;

        let mut path = String::new();
        let mut query = None;
        let mut fragment = None;

        // Fragment first: a fragment may itself contain "?".
        if let Some((before_fragment, frag)) = rest.split_once('#') {
            if !is_query_or_fragment(frag) {
                return Err(ParseError::Fragment);
            }

            fragment = Some(frag.into());
            rest = before_fragment;
        }

        if let Some((before_query, qry)) = rest.split_once('?') {
            if !is_query_or_fragment(qry) {
                return Err(ParseError::Query);
            }

            query = Some(qry.into());
            rest = before_query;
        }

        path.push_str(rest);

        // path-abempty  = *( "/" segment )
        let path_abempty = if path.is_empty() {
            None
        } else {
            if !path.starts_with('/') {
                return Err(ParseError::PathNotAbsolute);
            }

            if !path.split('/').all(|v| is_segment(v, Segment::Base)) {
                return Err(ParseError::PathSegment);
            }

            Some(path)
        };

        Ok(Self {
            did,
            path_abempty,
            query,
            fragment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full() {
        let did_url = DidUrl {
            did:          Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: Some("/path/to/resource".to_string()),
            query:        Some("key=value".into()),
            fragment:     Some("section".into()),
        };

        let serialized = did_url.to_string();
        assert_eq!(
            serialized,
            "did:example:123/path/to/resource?key=value#section"
        );

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_no_path() {
        let did_url = DidUrl {
            did:          Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: None,
            query:        Some("key=value".into()),
            fragment:     Some("section".into()),
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123?key=value#section");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_no_query() {
        let did_url = DidUrl {
            did:          Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: Some("/path/to/resource".to_string()),
            query:        None,
            fragment:     Some("section".into()),
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123/path/to/resource#section");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_no_fragment() {
        let did_url = DidUrl {
            did:          Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: Some("/path/to/resource".to_string()),
            query:        Some("key=value".into()),
            fragment:     None,
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123/path/to/resource?key=value");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_did_plain() {
        let did_url = DidUrl {
            did:          Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: None,
            query:        None,
            fragment:     None,
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_compound_query() {
        let did_url = DidUrl {
            did:          Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: None,
            query:        Some("a=1&b=2".into()),
            fragment:     None,
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123?a=1&b=2");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_rejects_control_characters() {
        for s in [
            "did:example:123?a=b\r\nX-Evil: 1",
            "did:example:123#frag with space",
            "did:example:123#trailing\n",
            "did:example:123?q=\0",
            "did:example:123/abc%4",
            "did:example:123/abc%",
            "did:example:123/p\u{430}th",
        ] {
            assert!(DidUrl::from_str(s).is_err(), "{s:?} should be rejected");
        }
    }

    #[test]
    fn test_fragment_may_contain_question_mark() {
        let url = DidUrl::from_str("did:example:123#frag?x").expect("valid");

        assert_eq!(url.fragment.as_deref(), Some("frag?x"));
        assert_eq!(url.query, None);
        assert_eq!(url.to_string(), "did:example:123#frag?x");
    }

    #[test]
    fn test_service_ref() {
        let did_url = DidUrl {
            did:          Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: None,
            query:        Some("service=my-service&relativeRef=/records/abc123".into()),
            fragment:     None,
        };

        let serialized = did_url.to_string();
        assert_eq!(
            serialized,
            "did:example:123?service=my-service&relativeRef=/records/abc123"
        );

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }
}
