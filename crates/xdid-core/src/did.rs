use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Did {
    pub method_name: MethodName,
    pub method_id: MethodId,
}

impl Serialize for Did {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let did_string = format!("did:{}:{}", self.method_name.0, self.method_id.0);
        serializer.serialize_str(&did_string)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let mut parts = s.splitn(3, ':');

        if parts.next() != Some("did") {
            return Err(serde::de::Error::custom("DID must start with 'did:'"));
        }

        let method_name = parts
            .next()
            .ok_or_else(|| serde::de::Error::custom("Missing method name"))?;
        let method_specific_id = parts
            .next()
            .ok_or_else(|| serde::de::Error::custom("Missing method-specific ID"))?;

        let method_name = MethodName::from_str(method_name).map_err(serde::de::Error::custom)?;
        let method_id = MethodId::from_str(method_specific_id).map_err(serde::de::Error::custom)?;

        Ok(Did {
            method_name,
            method_id,
        })
    }
}

impl FromStr for Did {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(Value::String(s.to_string()))
    }
}

impl Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        match value {
            Value::String(s) => write!(f, "{}", s),
            _ => Err(std::fmt::Error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodName(pub String);

impl FromStr for MethodName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            Ok(MethodName(s.to_string()))
        } else {
            Err("Method name must contain only lowercase letters and digits".into())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodId(pub String);

impl FromStr for MethodId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.split(':').all(is_valid_idchar) {
            Ok(MethodId(s.to_string()))
        } else {
            Err("Method-specific ID contains invalid characters".into())
        }
    }
}

fn is_valid_idchar(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '.'
            || c == '-'
            || c == '_'
            || c == '%'
            || c.is_ascii_hexdigit()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_example() {
        let did = Did {
            method_name: MethodName("example".to_string()),
            method_id: MethodId("1234-5678-abcdef".to_string()),
        };

        let serialized = did.to_string();
        assert_eq!(serialized, "did:example:1234-5678-abcdef");

        let deserialized = Did::from_str(&serialized).expect("deserialize failed");
        assert_eq!(deserialized, did);
    }
}
