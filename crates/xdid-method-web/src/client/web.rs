use reqwest::{
    Client,
    ClientBuilder,
    Response,
};
use xdid_core::ResolutionError;

use super::USER_AGENT;
use crate::{
    ClientError,
    Config,
};

/// The browser owns the transport, and exposes no controls for redirects,
/// timeouts or address selection. [`Config`]'s fields for those are documented
/// as inert here.
pub fn build(_config: &Config) -> Result<Client, ClientError> {
    ClientBuilder::new()
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| ClientError(e.to_string()))
}

/// The browser has already buffered the body, so the cap can only be enforced
/// after the fact.
pub async fn read_capped(res: Response, max: u64) -> Result<Vec<u8>, ResolutionError> {
    if res.content_length().is_some_and(|len| len > max) {
        return Err(ResolutionError::DocumentTooLarge);
    }

    let body = res.bytes().await.map_err(super::fetch_failed)?;

    if body.len() as u64 > max {
        return Err(ResolutionError::DocumentTooLarge);
    }

    Ok(body.to_vec())
}
