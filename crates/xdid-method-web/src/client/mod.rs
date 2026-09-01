use reqwest::{
    Client,
    Response,
};
use xdid_core::ResolutionError;

use crate::{
    ClientError,
    Config,
};

#[cfg(not(target_family = "wasm"))] mod native;
#[cfg(target_family = "wasm")] mod web;

const USER_AGENT: &str = concat!("xdid/", env!("CARGO_PKG_VERSION"));

/// Builds the HTTP client a resolution runs on.
pub fn build(config: &Config) -> Result<Client, ClientError> {
    cfg_select! {
        target_family = "wasm" => web::build(config),
        _ => native::build(config),
    }
}

/// Reads the response body, refusing one longer than `max`.
pub async fn read_capped(res: Response, max: u64) -> Result<Vec<u8>, ResolutionError> {
    cfg_select! {
        target_family = "wasm" => web::read_capped(res, max).await,
        _ => native::read_capped(res, max).await,
    }
}

/// Strips the URL from a transport error, which would otherwise let a caller
/// use resolution failures to probe internal hosts. A refusal this crate raised
/// itself is recovered first, since its own outcome is more specific.
pub fn fetch_failed(e: reqwest::Error) -> ResolutionError {
    let refusal = cfg_select! {
        target_family = "wasm" => None,
        _ => native::refusal(&e),
    };

    refusal.unwrap_or_else(|| ResolutionError::Transport(e.without_url().to_string()))
}
