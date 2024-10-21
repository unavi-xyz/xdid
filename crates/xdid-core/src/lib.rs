//! Core types for DID methods to implement.

use std::{future::Future, pin::Pin};

use did::Did;
use thiserror::Error;

pub mod did;
pub mod did_url;
pub mod document;

pub trait Method {
    fn method_name(&self) -> &'static str;

    /// Attempt to resolve the provided DID to its DID document.
    fn resolve(
        &self,
        did: Did,
    ) -> Pin<Box<dyn Future<Output = Result<document::Document, ResolutionError>>>>;
}

#[derive(Error, Debug)]
pub enum ResolutionError {
    #[error("unsupported method")]
    UnsupportedMethod,
    #[error("invalid DID")]
    InvalidDid,
}
