use std::{fmt::Display, str::FromStr};

use anyhow::bail;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use crate::uri::{Segment, is_segment};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelativeDidUrl {
    pub path: RelativeDidUrlPath,
    /// [DID query](https://www.w3.org/TR/did-core/#query) ([RFC 3986 - 3.4. Query](https://www.rfc-editor.org/rfc/rfc3986#section-3.4))
    pub query: Option<SmolStr>,
    /// [DID fragment](https://www.w3.org/TR/did-core/#fragment) ([RFC 3986 - 3.5. Fragment](https://www.rfc-editor.org/rfc/rfc3986#section-3.5))
    pub fragment: Option<SmolStr>,
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (path, query, fragment) = match s.split_once('?') {
            Some((path, rest)) => match rest.split_once('#') {
                Some((query, fragment)) => (path, Some(query), Some(fragment)),
                None => (path, Some(rest), None),
            },
            None => match s.split_once('#') {
                Some((path, fragment)) => (path, None, Some(fragment)),
                None => (s, None, None),
            },
        };

        Ok(Self {
            path: RelativeDidUrlPath::from_str(path)?,
            query: query.map(Into::into),
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

impl Display for RelativeDidUrlPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = match self {
            Self::Absolute(s) | Self::NoScheme(s) => s.as_str(),
            Self::Empty => "",
        };
        f.write_str(data)
    }
}

impl FromStr for RelativeDidUrlPath {
    type Err = anyhow::Error;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        if path.is_empty() {
            return Ok(Self::Empty);
        }
        if path.starts_with('/') {
            // path-absolute = "/" [ segment-nz *( "/" segment ) ]
            if path.len() >= 2 && path.chars().nth(1) == Some('/') {
                bail!("double slash at start")
            }

            if !path
                .split('/')
                .skip(1)
                .all(|v| is_segment(v, Segment::Base))
            {
                bail!("invalid segment")
            }

            Ok(Self::Absolute(path.to_string()))
        } else {
            // path-noscheme = segment-nz-nc *( "/" segment )
            if !path.split('/').all(|v| is_segment(v, Segment::NzNc)) {
                bail!("invalid segment")
            }

            Ok(Self::NoScheme(path.to_string()))
        }
    }
}
