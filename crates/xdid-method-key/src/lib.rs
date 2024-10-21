//! Implementation of [did:key](https://w3c-ccg.github.io/did-method-key/), using [xdid](https://github.com/unavi-xyz/xdid).

use multibase::Base;
use parser::DidKeyParser;
use xdid_core::{
    did::{Did, MethodId, MethodName},
    did_url::DidUrl,
    document::{Document, VerificationMethod, VerificationMethodMap},
    Method, ResolutionError,
};

pub mod keys;
mod parser;

const NAME: &str = "key";

pub struct DidKey {
    key: Box<dyn keys::PublicKey>,
}

impl DidKey {
    pub fn new(key: impl keys::PublicKey + 'static) -> Self {
        Self { key: Box::new(key) }
    }

    pub fn to_did(&self) -> Did {
        let key_bytes = self.key.public_key();

        let mut buffer = unsigned_varint::encode::u64_buffer();
        let code = unsigned_varint::encode::u64(self.key.public_code(), &mut buffer);

        let mut inner = Vec::with_capacity(code.len() + key_bytes.len());
        inner.extend(code);
        inner.extend(key_bytes);

        let id = multibase::encode(Base::Base58Btc, inner);

        Did {
            method_name: MethodName(NAME.to_string()),
            method_id: MethodId(id),
        }
    }
}

pub struct MethodDidKey;

impl Method for MethodDidKey {
    fn method_name(&self) -> &'static str {
        NAME
    }

    fn resolve(
        &self,
        did: Did,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Document, ResolutionError>>>>
    {
        debug_assert_eq!(did.method_name.0, self.method_name());

        Box::pin(async move {
            let parser = DidKeyParser::default();
            let did_key = parser
                .parse(&did)
                .map_err(|_| ResolutionError::InvalidDid)?;

            let did_url = DidUrl {
                did: did.clone(),
                path_abempty: String::new(),
                query: None,
                fragment: Some(did.method_id.0.clone()),
            };

            Ok(Document {
                id: did.clone(),
                also_known_as: None,
                controller: None,
                verification_method: Some(vec![VerificationMethodMap {
                    id: did_url.clone(),
                    typ: "JsonWebKey2020".to_string(),
                    controller: did.clone(),
                    public_key_jwk: Some(did_key.key.to_jwk()),
                    public_key_multibase: None,
                }]),
                authentication: Some(vec![VerificationMethod::URL(did_url.clone())]),
                assertion_method: Some(vec![VerificationMethod::URL(did_url.clone())]),
                capability_invocation: Some(vec![VerificationMethod::URL(did_url.clone())]),
                capability_delegation: Some(vec![VerificationMethod::URL(did_url)]),
                service: None,
                key_agreement: None,
            })
        })
    }
}
