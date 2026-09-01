use percent_encoding::percent_decode_str;
use reqwest::Url;
use thiserror::Error;
use xdid_core::did::Did;

use crate::target::TargetPolicy;

const WELL_KNOWN: &str = ".well-known";
const DOCUMENT: &str = "did.json";

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("empty domain")]
    EmptyDomain,
    #[error("method id is not valid percent-encoded UTF-8")]
    InvalidEncoding,
    #[error("path segment would traverse outside the DID path")]
    DotSegment,
    #[error("domain does not form a valid authority")]
    InvalidDomain,
}

/// Builds the document URL for a `did:web`.
pub fn parse_url(did: &Did, target: TargetPolicy) -> Result<Url, ParseError> {
    // web-did = "did:web:" domain-name *( ":" path )
    let mut parts = did.method_id.as_str().split(':');

    let domain = decode(parts.next().unwrap_or_default())?;
    if domain.is_empty() {
        return Err(ParseError::EmptyDomain);
    }

    let scheme = target.scheme_for(&domain);

    let mut url =
        Url::parse(&format!("{scheme}://{domain}")).map_err(|_| ParseError::InvalidDomain)?;

    // A decoded domain can smuggle userinfo or a path into the authority; the
    // parser reports those faithfully, so reject anything beyond a bare host.
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ParseError::InvalidDomain);
    }

    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| ParseError::InvalidDomain)?;
        segments.clear();

        let mut has_path = false;
        for part in parts {
            has_path = true;

            let segment = decode(part)?;
            if segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.contains('/')
                || segment.contains('\\')
            {
                return Err(ParseError::DotSegment);
            }

            segments.push(&segment);
        }

        if !has_path {
            segments.push(WELL_KNOWN);
        }

        segments.push(DOCUMENT);
    }

    Ok(url)
}

fn decode(value: &str) -> Result<String, ParseError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(Into::into)
        .map_err(|_| ParseError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn url_of(did: &str) -> Result<String, ParseError> {
        parse_url(
            &Did::from_str(did).expect("valid DID"),
            TargetPolicy::PublicOnly,
        )
        .map(String::from)
    }

    #[test]
    fn test_parse_no_path() {
        assert_eq!(
            url_of("did:web:w3c-ccg.github.io").expect("valid"),
            "https://w3c-ccg.github.io/.well-known/did.json"
        );
    }

    #[test]
    fn test_parse_path() {
        assert_eq!(
            url_of("did:web:w3c-ccg.github.io:user:alice").expect("valid"),
            "https://w3c-ccg.github.io/user/alice/did.json"
        );
    }

    #[test]
    fn test_parse_port() {
        assert_eq!(
            url_of("did:web:example.com%3A3000:user:alice").expect("valid"),
            "https://example.com:3000/user/alice/did.json"
        );
    }

    #[test]
    fn test_localhost_is_https() {
        assert_eq!(
            url_of("did:web:localhost%3A3000").expect("valid"),
            "https://localhost:3000/.well-known/did.json"
        );
    }

    #[test]
    fn test_rejects_dot_segments() {
        for did in [
            "did:web:evil.com:%2e%2e:%2e%2e:etc:passwd",
            "did:web:evil.com:user:%2e%2e:admin",
            "did:web:evil.com:%2e",
            "did:web:evil.com:a%2Fb",
        ] {
            assert!(url_of(did).is_err(), "{did} should be rejected");
        }
    }

    // An empty domain collapses the authority, so `https:///.well-known/did.json`
    // would resolve against a host named `.well-known`. Rejected by `MethodId`
    // before a `Did` can be built at all.
    #[test]
    fn test_empty_components_rejected_by_did_syntax() {
        for did in ["did:web:", "did:web:example.com:"] {
            assert!(Did::from_str(did).is_err(), "{did} should be rejected");
        }
    }

    #[test]
    fn test_rejects_smuggled_authority() {
        for did in [
            "did:web:user%40evil.com",
            "did:web:evil.com%2Fpath",
            "did:web:evil.com%3Fquery",
            "did:web:evil.com%23frag",
        ] {
            assert!(url_of(did).is_err(), "{did} should be rejected");
        }
    }

    #[test]
    fn test_interior_empty_segment_rejected() {
        assert!(url_of("did:web:example.com::user").is_err());
    }
}
