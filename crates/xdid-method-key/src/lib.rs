//! [xdid](https://github.com/unavi-xyz/xdid) implementation of [did:key](https://w3c-ccg.github.io/did-method-key/).

use parser::DidKeyParser;
use xdid_core::{
    Method, MethodFuture, ResolutionError,
    did::Did,
    did_url::DidUrl,
    document::{Document, VerificationMethod, VerificationMethodMap},
};

mod keys;
mod parser;

pub use keys::*;

const NAME: &str = "key";

pub struct MethodDidKey;

impl Method for MethodDidKey {
    fn method_name(&self) -> &'static str {
        NAME
    }

    fn resolve(&self, did: Did) -> MethodFuture<Result<Document, ResolutionError>> {
        Box::pin(async move { resolve_inner(did) })
    }
}

fn resolve_inner(did: Did) -> Result<Document, ResolutionError> {
    debug_assert_eq!(did.method_name.0, NAME);

    let parser = DidKeyParser::default();
    let did_key = parser
        .parse(&did)
        .map_err(|_| ResolutionError::InvalidDid)?;

    let did_url = DidUrl {
        did: did.clone(),
        fragment: Some(did.method_id.0.clone().into()),
        path_abempty: None,
        query: None,
    };

    Ok(Document {
        id: did.clone(),
        also_known_as: None,
        controller: None,
        verification_method: Some(vec![VerificationMethodMap {
            id: did_url.clone(),
            typ: "JsonWebKey2020".into(),
            controller: did,
            public_key_jwk: Some(did_key.to_jwk()),
            public_key_multibase: None,
        }]),
        authentication: Some(vec![VerificationMethod::Url(did_url.clone())]),
        assertion_method: Some(vec![VerificationMethod::Url(did_url.clone())]),
        capability_invocation: Some(vec![VerificationMethod::Url(did_url.clone())]),
        capability_delegation: Some(vec![VerificationMethod::Url(did_url)]),
        service: None,
        key_agreement: None,
    })
}
