use std::{fmt::Display, str::FromStr};

use anyhow::bail;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::{
    did::Did,
    uri::{Segment, is_segment},
};

use super::{RelativeDidUrl, RelativeDidUrlPath};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidUrl {
    pub did: Did,
    /// [DID path](https://www.w3.org/TR/did-core/#path). `path-abempty` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    pub path_abempty: Option<String>,
    /// [DID query](https://www.w3.org/TR/did-core/#query). `query` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    pub query: Option<SmolStr>,
    /// [DID fragment](https://www.w3.org/TR/did-core/#fragment). `fragment` component from
    /// [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    pub fragment: Option<SmolStr>,
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
    /// Attempts to convert the [`DidUrl`] into a [`RelativeDidUrl`].
    #[must_use]
    pub fn to_relative(&self) -> Option<RelativeDidUrl> {
        Some(RelativeDidUrl {
            path: match RelativeDidUrlPath::from_str(
                self.path_abempty.as_deref().unwrap_or_default(),
            ) {
                Ok(v) => v,
                Err(_) => return None,
            },
            fragment: self.fragment.clone(),
            query: self.query.clone(),
        })
    }
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let did_str = s.find(['/', '?', '#']).map_or(s, |pos| &s[..pos]);

        let did = Did::from_str(did_str)?;

        let mut path = String::new();
        let mut query = None;
        let mut fragment = None;

        let mut rest = s
            .strip_prefix(did_str)
            .expect("DID string prefix already validated");
        if let Some((before_fragment, frag)) = rest.split_once('#') {
            fragment = Some(frag.into());
            rest = before_fragment;
        }

        if let Some((before_query, qry)) = rest.split_once('?') {
            query = Some(qry.into());
            rest = before_query;
        }

        path.push_str(rest);

        // path-abempty  = *( "/" segment )
        let path_abempty = if path.is_empty() {
            None
        } else {
            if !path.starts_with('/') {
                bail!("path_abempty does not start with slash")
            }

            if !path.split('/').all(|v| is_segment(v, Segment::Base)) {
                bail!("invalid path_abempty segment")
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
            did: Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: Some("/path/to/resource".to_string()),
            query: Some("key=value".into()),
            fragment: Some("section".into()),
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
            did: Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: None,
            query: Some("key=value".into()),
            fragment: Some("section".into()),
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123?key=value#section");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_no_query() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: Some("/path/to/resource".to_string()),
            query: None,
            fragment: Some("section".into()),
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123/path/to/resource#section");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_no_fragment() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: Some("/path/to/resource".to_string()),
            query: Some("key=value".into()),
            fragment: None,
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123/path/to/resource?key=value");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_did_plain() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: None,
            query: None,
            fragment: None,
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_compound_query() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: None,
            query: Some("a=1&b=2".into()),
            fragment: None,
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123?a=1&b=2");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_dwn_ref() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").expect("valid DID"),
            path_abempty: None,
            query: Some("service=dwn&relativeRef=/records/abc123".into()),
            fragment: None,
        };

        let serialized = did_url.to_string();
        assert_eq!(
            serialized,
            "did:example:123?service=dwn&relativeRef=/records/abc123"
        );

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }
}
