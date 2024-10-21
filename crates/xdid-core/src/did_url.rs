use std::{fmt::Display, str::FromStr};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::did::Did;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidUrl {
    pub did: Did,
    pub path_abempty: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
}

impl Serialize for DidUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut url = format!("{}{}", self.did, self.path_abempty);

        if let Some(ref query) = self.query {
            url.push('?');
            url.push_str(query);
        }

        if let Some(ref fragment) = self.fragment {
            url.push('#');
            url.push_str(fragment);
        }

        serializer.serialize_str(&url)
    }
}

impl<'de> Deserialize<'de> for DidUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DidUrlVisitor;

        impl<'de> Visitor<'de> for DidUrlVisitor {
            type Value = DidUrl;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a valid DID URL")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let (did_str, _) = value.split_once('/').unwrap_or_else(|| {
                    value
                        .split_once('?')
                        .unwrap_or_else(|| value.split_once('#').unwrap_or((value, "")))
                });

                let did = Did::from_str(did_str).map_err(serde::de::Error::custom)?;

                let mut path_abempty = String::new();
                let mut query = None;
                let mut fragment = None;

                let mut rest = value.strip_prefix(did_str).unwrap();
                if let Some((before_fragment, frag)) = rest.split_once('#') {
                    fragment = Some(frag.to_string());
                    rest = before_fragment;
                }

                if let Some((before_query, qry)) = rest.split_once('?') {
                    query = Some(qry.to_string());
                    rest = before_query;
                }

                path_abempty.push_str(rest);

                Ok(DidUrl {
                    did,
                    path_abempty,
                    query,
                    fragment,
                })
            }
        }

        deserializer.deserialize_str(DidUrlVisitor)
    }
}

impl FromStr for DidUrl {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(Value::String(s.to_string()))
    }
}

impl Display for DidUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        match value {
            Value::String(s) => write!(f, "{}", s),
            _ => Err(std::fmt::Error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_url_full() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").unwrap(),
            path_abempty: "/path/to/resource".to_string(),
            query: Some("key=value".to_string()),
            fragment: Some("section".to_string()),
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
    fn test_did_url_no_path() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").unwrap(),
            path_abempty: "".to_string(),
            query: Some("key=value".to_string()),
            fragment: Some("section".to_string()),
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123?key=value#section");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_did_url_no_query() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").unwrap(),
            path_abempty: "/path/to/resource".to_string(),
            query: None,
            fragment: Some("section".to_string()),
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123/path/to/resource#section");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_did_url_no_fragment() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").unwrap(),
            path_abempty: "/path/to/resource".to_string(),
            query: Some("key=value".to_string()),
            fragment: None,
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123/path/to/resource?key=value");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }

    #[test]
    fn test_did_url_none() {
        let did_url = DidUrl {
            did: Did::from_str("did:example:123").unwrap(),
            path_abempty: "".to_string(),
            query: None,
            fragment: None,
        };

        let serialized = did_url.to_string();
        assert_eq!(serialized, "did:example:123");

        let deserialized = DidUrl::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did_url);
    }
}
