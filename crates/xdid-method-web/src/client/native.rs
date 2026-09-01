use std::{
    error::Error,
    fmt::{
        Display,
        Formatter,
    },
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use reqwest::{
    Client,
    ClientBuilder,
    Response,
    dns::{
        Addrs,
        Name,
        Resolve,
        Resolving,
    },
};
use rustls::crypto::CryptoProvider;
use xdid_core::ResolutionError;

use super::USER_AGENT;
use crate::{
    ClientError,
    Config,
    target::TargetPolicy,
};

/// `tls-ring` wins when both TLS features are enabled.
#[cfg(feature = "tls-ring")]
fn tls_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[cfg(feature = "tls-aws-lc-rs")]
#[cfg(not(feature = "tls-ring"))]
fn tls_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

pub fn build(config: &Config) -> Result<Client, ClientError> {
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
        .dns_resolver(Arc::new(PolicyResolver {
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

/// The outcome this module's own errors stand for, once [`reqwest`] has wrapped
/// them in its own.
pub fn refusal(e: &reqwest::Error) -> Option<ResolutionError> {
    let mut cause: Option<&(dyn Error + 'static)> = Some(e);

    while let Some(err) = cause {
        if err.downcast_ref::<RestrictedTarget>().is_some() {
            return Some(ResolutionError::TargetNotAllowed);
        }

        if err.downcast_ref::<TargetLookupTimedOut>().is_some() {
            return Some(ResolutionError::Transport("target lookup timed out".into()));
        }

        cause = err.source();
    }

    None
}

pub async fn read_capped(mut res: Response, max: u64) -> Result<Vec<u8>, ResolutionError> {
    if res.content_length().is_some_and(|len| len > max) {
        return Err(ResolutionError::DocumentTooLarge);
    }

    let cap = res.content_length().unwrap_or(0).min(max);
    let mut buf = Vec::with_capacity(usize::try_from(cap).unwrap_or(0));

    while let Some(chunk) = res.chunk().await.map_err(super::fetch_failed)? {
        if buf.len() as u64 + chunk.len() as u64 > max {
            return Err(ResolutionError::DocumentTooLarge);
        }

        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

/// A [`Resolve`] that rejects a hostname resolving to an address its policy
/// refuses, so validation and connection share one lookup instead of racing two
/// independent ones.
struct PolicyResolver {
    policy:  TargetPolicy,
    timeout: Duration,
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.policy;
        let timeout = self.timeout;
        let host = name.as_str().to_owned();

        Box::pin(async move {
            // The client's own timeouts start at connect, leaving this lookup
            // as the one unbounded phase of a resolve.
            let addrs: Vec<SocketAddr> =
                tokio::time::timeout(timeout, tokio::net::lookup_host((host.as_str(), 0)))
                    .await
                    .map_err(|_| Box::new(TargetLookupTimedOut) as Box<dyn Error + Send + Sync>)?
                    .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?
                    .collect();

            if addrs.is_empty() || !addrs.iter().all(|addr| policy.permits_address(addr.ip())) {
                return Err(Box::new(RestrictedTarget) as Box<dyn Error + Send + Sync>);
            }

            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[derive(Debug)]
struct RestrictedTarget;

impl Display for RestrictedTarget {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("target not allowed")
    }
}

impl Error for RestrictedTarget {}

#[derive(Debug)]
struct TargetLookupTimedOut;

impl Display for TargetLookupTimedOut {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("target lookup timed out")
    }
}

impl Error for TargetLookupTimedOut {}

#[cfg(test)]
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
        let name: Name = "localhost".parse().expect("valid name");

        let Err(err) = resolver_for(TargetPolicy::PublicOnly).resolve(name).await else {
            panic!("localhost resolves to a loopback address");
        };

        assert!(err.downcast_ref::<RestrictedTarget>().is_some(), "{err}");
    }

    #[tokio::test]
    async fn allow_local_resolves_the_same_hostname() {
        let name: Name = "localhost".parse().expect("valid name");

        let addrs = resolver_for(TargetPolicy::AllowLocal)
            .resolve(name)
            .await
            .expect("a loopback address is permitted under AllowLocal");

        assert!(addrs.count() > 0);
    }
}
