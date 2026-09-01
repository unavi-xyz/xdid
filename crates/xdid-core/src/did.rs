use std::{
    fmt::{
        Debug,
        Display,
    },
    str::FromStr,
};

use anyhow::bail;
use serde::{
    Deserialize,
    Serialize,
};
use smol_str::SmolStr;

use crate::uri::is_idchars;

/// A [decentralized identifier](https://www.w3.org/TR/did-core/#did-syntax).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Did {
    pub method_name: MethodName,
    pub method_id:   MethodId,
}

impl Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "did:{}:{}",
            self.method_name.as_str(),
            self.method_id.as_str()
        )
    }
}

impl Debug for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for Did {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, ':');

        if parts.next() != Some("did") {
            bail!("does not start with did")
        }

        let method_name = parts.next().ok_or_else(|| anyhow::anyhow!("no method"))?;
        let method_specific_id = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("no method id"))?;

        let method_name = MethodName::from_str(method_name)?;
        let method_id = MethodId::from_str(method_specific_id)?;

        Ok(Self {
            method_name,
            method_id,
        })
    }
}

impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v = self.to_string();
        serializer.serialize_str(&v)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|e| serde::de::Error::custom(format!("invalid DID: {e}")))
    }
}

/// The inner value is private so that a `MethodName` can only exist if it
/// satisfies the DID syntax; [`Did`] therefore needs no validation of its own.
#[derive(Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodName(SmolStr);

impl MethodName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for MethodName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MethodName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = SmolStr::deserialize(deserializer)?;
        Self::from_str(&s)
            .map_err(|e| serde::de::Error::custom(format!("invalid method name: {e}")))
    }
}

impl FromStr for MethodName {
    type Err = anyhow::Error;

    /// method-name = 1*method-char
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            bail!("method name is empty")
        }

        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            bail!("method name must contain only lowercase letters and digits")
        }

        Ok(Self(s.into()))
    }
}

/// The inner value is private; see [`MethodName`].
#[derive(Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodId(String);

impl MethodId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for MethodId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MethodId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|e| serde::de::Error::custom(format!("invalid method id: {e}")))
    }
}

impl FromStr for MethodId {
    type Err = anyhow::Error;

    /// method-specific-id = *( *idchar ":" ) 1*idchar
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The final colon-separated segment must be non-empty; interior ones
        // may be empty. An empty id collapses the authority of a
        // `did:web` URL.
        if s.is_empty() || s.ends_with(':') {
            bail!("method id must end with at least one idchar")
        }

        if !s.split(':').all(is_idchars) {
            bail!("method id contains invalid characters")
        }

        Ok(Self(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_example() {
        let did = Did {
            method_name: MethodName("example".into()),
            method_id:   MethodId("1234-5678-abcdef".to_string()),
        };

        let serialized = did.to_string();
        assert_eq!(serialized, "did:example:1234-5678-abcdef");

        let deserialized = Did::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did);
    }

    #[test]
    fn test_rejects_empty_components() {
        for s in ["did::abc", "did:example:", "did::", "did:example:a:"] {
            assert!(Did::from_str(s).is_err(), "{s} should be rejected");
        }
    }

    #[test]
    fn test_rejects_invalid_idchars() {
        for s in [
            "did:web:evil%zz",
            "did:web:evil%",
            "did:web:a~b",
            "did:web:a/b",
            "did:web:a b",
        ] {
            assert!(Did::from_str(s).is_err(), "{s} should be rejected");
        }
    }

    #[test]
    fn test_accepts_valid() {
        for s in [
            "did:web:example.com",
            "did:web:example.com%3A3000:user:alice",
            "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
            "did:example:a::b",
        ] {
            assert!(Did::from_str(s).is_ok(), "{s} should be accepted");
        }
    }
}
