//! [xdid](https://github.com/unavi-xyz/xdid) implementation of [did:web](https://w3c-ccg.github.io/did-method-web/).

#[cfg(all(not(feature = "tls-ring"), not(feature = "tls-aws-lc-rs")))]
compile_error!("xdid-method-web: enable `tls-ring` or `tls-aws-lc-rs`");

use std::time::Duration;

use reqwest::{
    Client,
    ClientBuilder,
    Response,
};
use thiserror::Error;
use xdid_core::{
    Method,
    MethodFuture,
    ResolutionError,
    did::Did,
    document::Document,
};

use crate::target::TargetPolicy;

mod parse;
pub mod target;

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
    /// Which hosts a resolution may reach.
    ///
    /// [`TargetPolicy::PublicOnly`] also disables the system proxy, since a
    /// proxy resolves the target host itself and would bypass the address
    /// checks.
    pub target:             TargetPolicy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_document_bytes: 64 * 1024,
            connect_timeout:    Duration::from_secs(5),
            request_timeout:    Duration::from_secs(10),
            target:             TargetPolicy::PublicOnly,
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

    let mut builder = ClientBuilder::new()
        .use_preconfigured_tls(tls)
        .user_agent(USER_AGENT)
        // A redirect would escape the target checks applied to the initial URL.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        // Judges the address the connector goes on to use, so validation and
        // connection share one lookup instead of racing two a hostile resolver
        // could answer differently.
        .dns_resolver(std::sync::Arc::new(PolicyResolver {
            policy:  config.target,
            timeout: config.connect_timeout,
        }));

    if config.target == TargetPolicy::PublicOnly {
        // A proxy resolves the target host itself and connects on our behalf,
        // so the resolver above would only ever see the proxy's own address.
        builder = builder.no_proxy().https_only(true);
    }

    builder.build().map_err(|e| ClientError(e.to_string()))
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
        // Sound only because wasm is single-threaded; the future is never
        // polled from a thread other than the one that created it.
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

    let mut url = parse::parse_url(&did).map_err(|_| ResolutionError::InvalidDid)?;
    config.target.downgrade_local_scheme(&mut url);

    config
        .target
        .permits_url(&url)
        .map_err(|_| ResolutionError::TargetNotAllowed)?;

    let res = client
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            "application/did+json, application/json",
        )
        .send()
        .await
        .map_err(fetch_failed)?;

    // A refused redirect arrives as a 3xx carrying no document, which would
    // otherwise be reported as malformed JSON.
    if !res.status().is_success() {
        return Err(ResolutionError::ResolutionFailed(format!(
            "unexpected status {}",
            res.status()
        )));
    }

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
/// resolution failures to probe internal hosts. `RestrictedResolver` rejections
/// are unwrapped back to their specific `ResolutionError` first.
fn fetch_failed(e: reqwest::Error) -> ResolutionError {
    #[cfg(not(target_family = "wasm"))]
    {
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&e);
        while let Some(err) = cause {
            if err.downcast_ref::<RestrictedTarget>().is_some() {
                return ResolutionError::TargetNotAllowed;
            }
            if err.downcast_ref::<TargetLookupTimedOut>().is_some() {
                return ResolutionError::ResolutionFailed("target lookup timed out".into());
            }
            cause = err.source();
        }
    }

    ResolutionError::ResolutionFailed(e.without_url().to_string())
}

/// A [`reqwest::dns::Resolve`] that rejects a hostname resolving to an address
/// its policy refuses, so validation and connection share one lookup instead
/// of racing two independent ones.
#[cfg(not(target_family = "wasm"))]
struct PolicyResolver {
    policy:  TargetPolicy,
    timeout: Duration,
}

#[cfg(not(target_family = "wasm"))]
impl reqwest::dns::Resolve for PolicyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = self.policy;
        let timeout = self.timeout;
        let host = name.as_str().to_owned();

        Box::pin(async move {
            // The client's own timeouts start at connect, leaving this lookup
            // as the one unbounded phase of a resolve.
            let addrs: Vec<std::net::SocketAddr> =
                tokio::time::timeout(timeout, tokio::net::lookup_host((host.as_str(), 0)))
                    .await
                    .map_err(|_| {
                        Box::new(TargetLookupTimedOut) as Box<dyn std::error::Error + Send + Sync>
                    })?
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                    .collect();

            if addrs.is_empty() || !addrs.iter().all(|addr| policy.permits_address(addr.ip())) {
                return Err(Box::new(RestrictedTarget) as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
struct RestrictedTarget;

#[cfg(not(target_family = "wasm"))]
impl std::fmt::Display for RestrictedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("target not allowed")
    }
}

#[cfg(not(target_family = "wasm"))]
impl std::error::Error for RestrictedTarget {}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
struct TargetLookupTimedOut;

#[cfg(not(target_family = "wasm"))]
impl std::fmt::Display for TargetLookupTimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("target lookup timed out")
    }
}

#[cfg(not(target_family = "wasm"))]
impl std::error::Error for TargetLookupTimedOut {}

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

    const fn resolver_for(policy: TargetPolicy) -> PolicyResolver {
        PolicyResolver {
            policy,
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn a_hostname_resolving_to_a_restricted_address_is_rejected() {
        let name: reqwest::dns::Name = "localhost".parse().expect("valid name");

        let Err(err) =
            reqwest::dns::Resolve::resolve(&resolver_for(TargetPolicy::PublicOnly), name).await
        else {
            panic!("localhost resolves to a loopback address");
        };

        assert!(err.downcast_ref::<RestrictedTarget>().is_some(), "{err}");
    }

    #[tokio::test]
    async fn allow_local_resolves_the_same_hostname() {
        let name: reqwest::dns::Name = "localhost".parse().expect("valid name");

        let addrs = reqwest::dns::Resolve::resolve(&resolver_for(TargetPolicy::AllowLocal), name)
            .await
            .expect("a loopback address is permitted under AllowLocal");

        assert!(addrs.count() > 0);
    }
}
