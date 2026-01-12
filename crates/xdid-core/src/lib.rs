//! Core types for DID methods to implement.

use std::{future::Future, pin::Pin};

use did::Did;
use thiserror::Error;

pub mod did;
pub mod did_url;
pub mod document;
mod uri;

/// Boxed future for [`Method::resolve`].
pub type MethodFuture<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;

pub trait Method: Send + Sync {
    fn method_name(&self) -> &'static str;
    fn resolve(&self, did: Did) -> MethodFuture<Result<document::Document, ResolutionError>>;
}

#[derive(Error, Debug)]
pub enum ResolutionError {
    #[error("invalid DID")]
    InvalidDid,
    #[error("resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("unsupported method")]
    UnsupportedMethod,
}
