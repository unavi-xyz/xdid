//! [xdid](https://github.com/unavi-xyz/xdid) implementation of [did:web](https://w3c-ccg.github.io/did-method-web/).

#[cfg(all(not(feature = "tls-ring"), not(feature = "tls-aws-lc-rs")))]
compile_error!("xdid-method-web: enable `tls-ring` or `tls-aws-lc-rs`");

use std::time::Duration;

use reqwest::{
    Client,
    ClientBuilder,
    Response,
    Url,
};
use thiserror::Error;
use xdid_core::{
    Method,
    MethodFuture,
    ResolutionError,
    did::Did,
    document::Document,
};

mod parse;
mod policy;

const NAME: &str = "web";
const USER_AGENT: &str = concat!("xdid/", env!("CARGO_PKG_VERSION"));

/// Limits applied while resolving. The defaults assume DIDs arrive from
/// untrusted input.
#[derive(Debug, Clone)]
pub struct Config {
    /// Rejects documents larger than this, streaming the body so an oversized
    /// or dishonestly-framed response is abandoned rather than buffered.
    pub max_document_bytes: u64,
    pub connect_timeout:    Duration,
    pub request_timeout:    Duration,
    /// Permits loopback, private and link-local targets, and plaintext HTTP for
    /// `localhost`. Needed to resolve against a local server; an SSRF vector
    /// whenever the DID being resolved is attacker-controlled.
    pub allow_local:        bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_document_bytes: 64 * 1024,
            connect_timeout:    Duration::from_secs(5),
            request_timeout:    Duration::from_secs(10),
            allow_local:        false,
        }
    }
}

/// Keeps `reqwest` out of the public API, where its version would otherwise be
/// part of this crate's semver contract.
#[derive(Debug, Error)]
#[error("failed to build the HTTP client: {0}")]
pub struct ClientError(String);

pub struct MethodDidWeb {
    client: Client,
    config: Config,
}

impl MethodDidWeb {
    /// Create a new did:web resolver.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new() -> Result<Self, ClientError> {
        Self::with_config(Config::default())
    }

    /// Create a new did:web resolver with the given [`Config`].
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn with_config(config: Config) -> Result<Self, ClientError> {
        let client = build_client(&config)?;
        Ok(Self { client, config })
    }
}

/// `tls-ring` wins when both TLS features are enabled.
#[cfg(not(target_family = "wasm"))]
#[cfg(feature = "tls-ring")]
fn tls_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}

#[cfg(not(target_family = "wasm"))]
#[cfg(feature = "tls-aws-lc-rs")]
#[cfg(not(feature = "tls-ring"))]
fn tls_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

#[cfg(not(target_family = "wasm"))]
fn build_client(config: &Config) -> Result<Client, ClientError> {
    use rustls_platform_verifier::BuilderVerifierExt;

    let tls = rustls::ClientConfig::builder_with_provider(tls_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError(e.to_string()))?
        .with_platform_verifier()
        .map_err(|e| ClientError(e.to_string()))?
        .with_no_client_auth();

    ClientBuilder::new()
        .use_preconfigured_tls(tls)
        .user_agent(USER_AGENT)
        // A redirect would escape the target checks applied to the initial URL.
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!config.allow_local)
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .build()
        .map_err(|e| ClientError(e.to_string()))
}

// The wasm client is the browser's; it applies its own transport policy and
// exposes no knobs for redirects or timeouts.
#[cfg(target_family = "wasm")]
fn build_client(_config: &Config) -> Result<Client, ClientError> {
    ClientBuilder::new()
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| ClientError(e.to_string()))
}

impl Method for MethodDidWeb {
    fn method_name(&self) -> &'static str {
        NAME
    }

    #[cfg(not(target_family = "wasm"))]
    fn resolve(&self, did: Did) -> MethodFuture<Result<Document, ResolutionError>> {
        Box::pin(resolve_inner(self.client.clone(), self.config.clone(), did))
    }

    #[cfg(target_family = "wasm")]
    fn resolve(&self, did: Did) -> MethodFuture<Result<Document, ResolutionError>> {
        // Sound only because wasm is single-threaded; the future is never polled
        // from a thread other than the one that created it.
        Box::pin(send_wrapper::SendWrapper::new(resolve_inner(
            self.client.clone(),
            self.config.clone(),
            did,
        )))
    }
}

async fn resolve_inner(
    client: Client,
    config: Config,
    did: Did,
) -> Result<Document, ResolutionError> {
    if did.method_name.as_str() != NAME {
        return Err(ResolutionError::InvalidDid);
    }

    let url =
        parse::parse_url(&did, config.allow_local).map_err(|_| ResolutionError::InvalidDid)?;

    if !config.allow_local {
        check_target(&url, config.connect_timeout).await?;
    }

    let res = client
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            "application/did+json, application/json",
        )
        .send()
        .await
        .map_err(fetch_failed)?
        .error_for_status()
        .map_err(fetch_failed)?;

    let body = read_capped(res, config.max_document_bytes).await?;

    let doc = serde_json::from_slice::<Document>(&body)
        .map_err(|e| ResolutionError::ResolutionFailed(e.to_string()))?;

    // Without this the host of `did:web:evil.com` can serve a document claiming
    // to be any other DID, and callers keying off `doc.id` attribute the
    // attacker's keys to that identifier.
    if doc.id != did {
        return Err(ResolutionError::DocumentMismatch);
    }

    Ok(doc)
}

/// Strips the URL from transport errors, which would otherwise let a caller use
/// resolution failures to probe internal hosts.
fn fetch_failed(e: reqwest::Error) -> ResolutionError {
    ResolutionError::ResolutionFailed(e.without_url().to_string())
}

/// Rejects targets outside public unicast space before any connection is made.
///
/// The addresses are re-resolved by the connector, so a hostile resolver can
/// still return a public address here and a private one there. Closing that
/// race needs a custom connector that checks the peer at connect time.
#[cfg(not(target_family = "wasm"))]
async fn check_target(url: &Url, timeout: Duration) -> Result<(), ResolutionError> {
    use std::net::IpAddr;

    let host = url.host_str().ok_or(ResolutionError::InvalidDid)?;
    let port = url.port_or_known_default().unwrap_or(443);

    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let addrs = if let Ok(ip) = bare.parse::<IpAddr>() {
        vec![ip]
    } else {
        // The client's own timeouts start at connect, leaving this lookup as the
        // one unbounded phase of a resolve.
        tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
            .await
            .map_err(|_| ResolutionError::ResolutionFailed("target lookup timed out".into()))?
            .map_err(|e| ResolutionError::ResolutionFailed(e.to_string()))?
            .map(|addr| addr.ip())
            .collect()
    };

    if addrs.is_empty() || addrs.iter().copied().any(policy::is_restricted) {
        return Err(ResolutionError::TargetNotAllowed);
    }

    Ok(())
}

#[cfg(target_family = "wasm")]
async fn check_target(_url: &Url, _timeout: Duration) -> Result<(), ResolutionError> {
    Ok(())
}

#[cfg(not(target_family = "wasm"))]
async fn read_capped(mut res: Response, max: u64) -> Result<Vec<u8>, ResolutionError> {
    if res.content_length().is_some_and(|len| len > max) {
        return Err(ResolutionError::DocumentTooLarge);
    }

    let cap = res.content_length().unwrap_or(0).min(max);
    let mut buf = Vec::with_capacity(usize::try_from(cap).unwrap_or(0));

    while let Some(chunk) = res.chunk().await.map_err(fetch_failed)? {
        if buf.len() as u64 + chunk.len() as u64 > max {
            return Err(ResolutionError::DocumentTooLarge);
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

// The browser has already buffered the body, so the cap can only be enforced
// after the fact.
#[cfg(target_family = "wasm")]
async fn read_capped(res: Response, max: u64) -> Result<Vec<u8>, ResolutionError> {
    if res.content_length().is_some_and(|len| len > max) {
        return Err(ResolutionError::DocumentTooLarge);
    }

    let body = res.bytes().await.map_err(fetch_failed)?;
    if body.len() as u64 > max {
        return Err(ResolutionError::DocumentTooLarge);
    }

    Ok(body.to_vec())
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_literal_target_is_checked_without_a_lookup() {
        let public = Url::parse("https://93.184.216.34/.well-known/did.json").expect("valid url");
        let private = Url::parse("https://10.0.0.1/.well-known/did.json").expect("valid url");

        assert!(check_target(&public, Duration::ZERO).await.is_ok());
        assert!(matches!(
            check_target(&private, Duration::ZERO).await,
            Err(ResolutionError::TargetNotAllowed)
        ));
    }
}
