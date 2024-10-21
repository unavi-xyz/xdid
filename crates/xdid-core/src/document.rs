use jose_jwk::Jwk;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none};

use crate::{did::Did, did_url::DidUrl};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[serde_as]
#[skip_serializing_none]
pub struct Document {
    pub id: Did,
    pub also_known_as: Option<Vec<String>>,
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub controller: Option<Vec<Did>>,
    pub verification_method: Option<Vec<VerificationMethodMap>>,
    pub authentication: Option<Vec<VerificationMethod>>,
    pub assertion_method: Option<Vec<VerificationMethod>>,
    pub key_agreement: Option<Vec<VerificationMethod>>,
    pub capability_invocation: Option<Vec<VerificationMethod>>,
    pub capability_delegation: Option<Vec<VerificationMethod>>,
    pub service: Option<Vec<ServiceEndpoint>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum VerificationMethod {
    Map(VerificationMethodMap),
    URL(DidUrl),
}

#[derive(Serialize, Deserialize, Debug)]
#[skip_serializing_none]
pub struct VerificationMethodMap {
    pub id: DidUrl,
    pub controller: Did,
    #[serde(rename = "type")]
    pub typ: String,
    pub public_key_jwk: Option<Jwk>,
    /// Multibase encoded public key.
    pub public_key_multibase: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde_as]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_>")]
    pub typ: Vec<String>,
}
