//! Core types for DID methods to implement.

use std::future::Future;

use thiserror::Error;

pub mod did;
pub mod did_url;
pub mod document;

/// DID method.
pub trait Method {
    fn resolve(&self) -> impl Future<Output = Result<document::Document, ResolutionError>>;
}

#[derive(Error, Debug)]
pub enum ResolutionError {}
