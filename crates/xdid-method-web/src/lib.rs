//! [xdid](https://github.com/unavi-xyz/xdid) implementation of [did:web](https://w3c-ccg.github.io/did-method-web/).

#[cfg(all(not(feature = "tls-ring"), not(feature = "tls-aws-lc-rs")))]
compile_error!("xdid-method-web: enable `tls-ring` or `tls-aws-lc-rs`");

use std::time::Duration;

use reqwest::Client;
use thiserror::Error;
use xdid_core::{
    Method,
    MethodFuture,
    ResolutionError,
    did::Did,
    document::Document,
};

use crate::target::TargetPolicy;

mod client;
mod parse;
mod resolve;
pub mod target;

const NAME: &str = "web";

/// Limits applied while resolving. The defaults assume DIDs arrive from
/// untrusted input.
///
/// A browser build gets the transport the browser gives it, which exposes no
/// controls for redirects, timeouts or address selection. Each field below says
/// what survives there.
#[derive(Debug, Clone)]
pub struct Config {
    /// Rejects documents larger than this. A native build streams the body, so
    /// an oversized or dishonestly-framed response is abandoned rather than
    /// buffered; a browser build has already buffered it and can only check
    /// afterwards.
    pub max_document_bytes: u64,
    /// Ignored by a browser build.
    pub connect_timeout:    Duration,
    /// Ignored by a browser build.
    pub request_timeout:    Duration,
    /// Which hosts a resolution may reach.
    ///
    /// [`TargetPolicy::PublicOnly`] also disables the system proxy, since a
    /// proxy resolves the target host itself and would bypass the address
    /// checks.
    ///
    /// A browser build applies the scheme rule and refuses a literal address,
    /// but cannot judge the address a hostname resolves to.
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
        let client = client::build(&config)?;
        Ok(Self { client, config })
    }
}

impl Method for MethodDidWeb {
    fn method_name(&self) -> &'static str {
        NAME
    }

    fn resolve<'a>(&'a self, did: &'a Did) -> MethodFuture<'a, Result<Document, ResolutionError>> {
        cfg_select! {
            target_family = "wasm" => Box::pin(resolve::bridged(
                self.client.clone(),
                self.config.clone(),
                did.clone(),
            )),
            _ => Box::pin(resolve::document(&self.client, &self.config, did)),
        }
    }
}
