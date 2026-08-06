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
    /// Detail never includes the resolved URL, which would make resolution
    /// errors an oracle for probing internal hosts.
    #[error("resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("unsupported method")]
    UnsupportedMethod,
}
