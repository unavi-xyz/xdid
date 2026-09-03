#[cfg(target_family = "wasm")]
use futures::channel::oneshot;
use reqwest::{
    Client,
    StatusCode,
};
use xdid_core::{
    ResolutionError,
    did::Did,
    document::Document,
};

use crate::{
    Config,
    NAME,
    client,
    parse,
};

/// A browser's `fetch` future is `!Send`, so it cannot be awaited where the
/// caller's future must be `Send`. It runs on the browser's own executor and
/// the result travels back over a channel.
#[cfg(target_family = "wasm")]
pub async fn bridged(
    client: Client,
    config: Config,
    did: Did,
) -> Result<Document, ResolutionError> {
    let (tx, rx) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        if tx.send(document(&client, &config, &did).await).is_err() {
            // The awaiting side was dropped before the fetch ended, so the
            // outcome has no listener.
        }
    });
    rx.await
        .map_err(|_| ResolutionError::Transport("resolution was cancelled".into()))?
}

/// Fetches `did`'s document and checks that it speaks for `did`.
pub async fn document(
    client: &Client,
    config: &Config,
    did: &Did,
) -> Result<Document, ResolutionError> {
    if did.method_name.as_str() != NAME {
        return Err(ResolutionError::InvalidDid);
    }

    let url = parse::parse_url(did, config.target).map_err(|_| ResolutionError::InvalidDid)?;

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
        .map_err(client::fetch_failed)?;

    if res.status() == StatusCode::NOT_FOUND {
        return Err(ResolutionError::NotFound);
    }

    // A refused redirect arrives as a 3xx carrying no document, which would
    // otherwise be reported as malformed JSON.
    if !res.status().is_success() {
        return Err(ResolutionError::Transport(format!(
            "unexpected status {}",
            res.status()
        )));
    }

    let body = client::read_capped(res, config.max_document_bytes).await?;

    let doc = serde_json::from_slice::<Document>(&body)
        .map_err(|e| ResolutionError::Malformed(e.to_string()))?;

    // Without this the host of `did:web:evil.com` can serve a document claiming
    // to be any other DID, and callers keying off `doc.id` attribute the
    // attacker's keys to that identifier.
    if doc.id != *did {
        return Err(ResolutionError::DocumentMismatch);
    }

    Ok(doc)
}
