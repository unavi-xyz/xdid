//! Core types for DID methods to implement.

use std::{
    future::Future,
    pin::Pin,
};

use did::Did;
use thiserror::Error;

pub mod did;
pub mod did_url;
pub mod document;
mod uri;

/// Boxed future for [`Method::resolve`].
pub type MethodFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub trait Method: Send + Sync {
    fn method_name(&self) -> &'static str;
    fn resolve(&self, did: Did) -> MethodFuture<Result<document::Document, ResolutionError>>;
}

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ResolutionError {
    #[error("invalid DID")]
    InvalidDid,
    /// The resolved document's `id` was not the DID being resolved, so the
    /// document speaks for an identifier its host does not control.
    #[error("document id does not match the resolved DID")]
    DocumentMismatch,
    /// The target was rejected before any request was sent.
    #[error("resolution target is not permitted")]
    TargetNotAllowed,
    #[error("document exceeds the configured size limit")]
    DocumentTooLarge,
    /// The host answered, and publishes no document for this DID. A caller
    /// should not retry, and should not treat the DID as merely unreachable.
    #[error("no document is published for this DID")]
    NotFound,
    /// The host could not be reached, or answered in a way that says nothing
    /// about the DID. Worth retrying.
    ///
    /// Detail never includes the resolved URL, which would make resolution
    /// errors an oracle for probing internal hosts.
    #[error("could not reach the DID's host: {0}")]
    Transport(String),
    /// The host answered with something that is not a DID document.
    #[error("response is not a DID document: {0}")]
    Malformed(String),
    #[error("unsupported method")]
    UnsupportedMethod,
}
