use jose_jwk::Jwk;
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::Value;
use serde_with::{
    serde_as,
    skip_serializing_none,
};
use smol_str::SmolStr;

use crate::{
    did::Did,
    did_url::{
        DidUrl,
        relative::RelativeDidUrl,
    },
};

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde_as]
pub struct Document {
    /// Held as opaque JSON so that re-serializing a resolved document does not
    /// drop it. Entries may be strings or objects and are never interpreted.
    #[serde(rename = "@context")]
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub context:               Option<Vec<Value>>,
    pub id:                    Did,
    /// Identifiers the subject claims are also theirs. The DID spec makes
    /// these claims rather than assertions, and nothing here verifies them.
    /// Confirming one means resolving it and finding a matching claim back.
    pub also_known_as:         Option<Vec<String>>,
    /// Supplied by whoever served the document, and not verified.
    ///
    /// A hostile document naming another DID here cannot mislead
    /// [`Self::resolve_verification_method`] or its siblings, which compare
    /// each method's own `id` against [`Self::id`] and never read this. Code
    /// that reads it directly is what needs to be careful.
    #[serde_as(as = "Option<OneOrMany<_>>")]
    pub controller:            Option<Vec<Did>>,
    pub verification_method:   Option<Vec<VerificationMethodMap>>,
    pub authentication:        Option<Vec<VerificationMethod>>,
    pub assertion_method:      Option<Vec<VerificationMethod>>,
    pub key_agreement:         Option<Vec<VerificationMethod>>,
    pub capability_invocation: Option<Vec<VerificationMethod>>,
    pub capability_delegation: Option<Vec<VerificationMethod>>,
    pub service:               Option<Vec<ServiceEndpoint>>,
}

impl Document {
    /// An otherwise empty document for `id`.
    #[must_use]
    pub const fn new(id: Did) -> Self {
        Self {
            context: None,
            id,
            also_known_as: None,
            controller: None,
            verification_method: None,
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            service: None,
        }
    }

    /// The verification methods this document lists under `role`, resolved to
    /// the maps that carry their key material.
    ///
    /// A method whose `id` names a different DID is skipped, so a document
    /// cannot present another identifier's key as usable under one of its own
    /// relationships. An entry that resolves to nothing is skipped too.
    pub fn verification_methods(
        &self,
        role: VerificationRole,
    ) -> impl Iterator<Item = &VerificationMethodMap> {
        self.methods_for(role)
            .iter()
            .filter_map(|method| self.resolve_verification_method(method))
    }

    fn methods_for(&self, role: VerificationRole) -> &[VerificationMethod] {
        match role {
            VerificationRole::Assertion => self.assertion_method.as_deref(),
            VerificationRole::Authentication => self.authentication.as_deref(),
            VerificationRole::CapabilityDelegation => self.capability_delegation.as_deref(),
            VerificationRole::CapabilityInvocation => self.capability_invocation.as_deref(),
            VerificationRole::KeyAgreement => self.key_agreement.as_deref(),
        }
        .unwrap_or_default()
    }

    /// Returns the verification method that the provided [`DidUrl`] is
    /// referencing, restricted to a given [`VerificationRole`].
    ///
    /// Runs in `O(roles + methods)`. Resolving every entry and then comparing
    /// would be quadratic, which a hostile document can turn into seconds of
    /// CPU for a few megabytes of input.
    #[must_use]
    pub fn resolve_verification_method_url(
        &self,
        url: &DidUrl,
        role: VerificationRole,
    ) -> Option<&VerificationMethodMap> {
        // Every reference that denotes `url` resolves to the same map, so the
        // scan over `verification_method` happens at most once.
        let mut referenced = None;

        for method in self.methods_for(role) {
            let denotes_url = match method {
                VerificationMethod::Map(map) => {
                    if map.id == *url && *map.id.did() == self.id {
                        return Some(map);
                    }
                    continue;
                }
                VerificationMethod::RelativeUrl(relative) => url.matches_relative(relative),
                VerificationMethod::Url(reference) => reference == url,
            };

            if denotes_url
                && let Some(found) = *referenced.get_or_insert_with(|| self.lookup_method(url))
            {
                return Some(found);
            }
        }

        None
    }

    fn lookup_method(&self, url: &DidUrl) -> Option<&VerificationMethodMap> {
        if *url.did() != self.id {
            return None;
        }

        self.verification_method
            .as_deref()?
            .iter()
            .find(|method| method.id == *url)
    }

    /// Resolves a [`VerificationMethod`] to its [`VerificationMethodMap`].
    /// For embedded maps, returns the map directly. For URL references,
    /// resolves them against this document's `verification_method` array.
    ///
    /// A method whose `id` names a different DID is never returned: otherwise a
    /// document could embed a method claiming to be another identifier's key.
    /// Its `controller` may name another DID, which this does not verify.
    #[must_use]
    pub fn resolve_verification_method<'a>(
        &'a self,
        method: &'a VerificationMethod,
    ) -> Option<&'a VerificationMethodMap> {
        let map = match method {
            VerificationMethod::Map(map) => map.as_ref(),
            VerificationMethod::RelativeUrl(relative_url) => {
                self.resolve_relative_url(relative_url)?
            }
            VerificationMethod::Url(url) => {
                if *url.did() != self.id {
                    // TODO: Support additional DID resolution?
                    return None;
                }

                self.resolve_relative_url(&url.to_relative()?)?
            }
        };

        (*map.id.did() == self.id).then_some(map)
    }

    fn resolve_relative_url(&self, url: &RelativeDidUrl) -> Option<&VerificationMethodMap> {
        self.verification_method
            .as_deref()?
            .iter()
            .find(|method| method.id.matches_relative(url))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum VerificationRole {
    Assertion,
    Authentication,
    CapabilityDelegation,
    CapabilityInvocation,
    KeyAgreement,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum VerificationMethod {
    Map(Box<VerificationMethodMap>),
    RelativeUrl(RelativeDidUrl),
    Url(DidUrl),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct VerificationMethodMap {
    pub id:                   DidUrl,
    pub controller:           Did,
    #[serde(rename = "type")]
    pub typ:                  SmolStr,
    pub public_key_jwk:       Option<Jwk>,
    /// Multibase encoded public key.
    pub public_key_multibase: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde_as]
pub struct ServiceEndpoint {
    pub id:               String,
    #[serde(rename = "type")]
    #[serde_as(as = "OneOrMany<_>")]
    pub typ:              Vec<String>,
    /// Supplied by whoever served the document, and not validated here.
    ///
    /// Fetching one carries the same server-side request forgery exposure as
    /// resolving the DID itself, so judge it with the same target policy the
    /// resolver used. `xdid-method-web` exposes that as `TargetPolicy`.
    #[serde_as(as = "OneOrMany<_>")]
    pub service_endpoint: Vec<String>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use smol_str::SmolStr;

    use super::*;
    use crate::did_url::relative::RelativeDidUrlPath;

    fn did(s: &str) -> Did {
        Did::from_str(s).expect("valid DID")
    }

    fn url(did: &Did, fragment: &str) -> DidUrl {
        DidUrl::new(did.clone(), None, None, Some(SmolStr::new(fragment))).expect("valid DID URL")
    }

    fn map(id: DidUrl, controller: &Did) -> VerificationMethodMap {
        VerificationMethodMap {
            id,
            controller: controller.clone(),
            typ: "JsonWebKey2020".into(),
            public_key_jwk: None,
            public_key_multibase: None,
        }
    }

    fn document(id: Did, authentication: Vec<VerificationMethod>) -> Document {
        Document {
            authentication: Some(authentication),
            ..Document::new(id)
        }
    }

    #[test]
    fn resolves_embedded_map() {
        let me = did("did:web:example.com");
        let key = url(&me, "key1");
        let mut doc = document(
            me.clone(),
            vec![VerificationMethod::Map(Box::new(map(key.clone(), &me)))],
        );
        doc.verification_method = None;

        assert_eq!(
            doc.resolve_verification_method_url(&key, VerificationRole::Authentication),
            Some(&map(key.clone(), &me))
        );
    }

    #[test]
    fn resolves_absolute_and_relative_references() {
        let me = did("did:web:example.com");
        let key = url(&me, "key1");

        let relative =
            RelativeDidUrl::new(RelativeDidUrlPath::Empty, None, Some(SmolStr::new("key1")))
                .expect("valid relative DID URL");

        for reference in [
            VerificationMethod::Url(key.clone()),
            VerificationMethod::RelativeUrl(relative),
        ] {
            let mut doc = document(me.clone(), vec![reference]);
            doc.verification_method = Some(vec![map(key.clone(), &me)]);

            assert_eq!(
                doc.resolve_verification_method_url(&key, VerificationRole::Authentication),
                Some(&map(key.clone(), &me))
            );
        }
    }

    #[test]
    fn returns_none_for_unlisted_url() {
        let me = did("did:web:example.com");
        let key = url(&me, "key1");
        let other = url(&me, "key2");

        let mut doc = document(me.clone(), vec![VerificationMethod::Url(key.clone())]);
        doc.verification_method = Some(vec![map(key, &me)]);

        assert_eq!(
            doc.resolve_verification_method_url(&other, VerificationRole::Authentication),
            None
        );
    }

    #[test]
    fn rejects_embedded_map_claiming_another_did() {
        let attacker = did("did:web:evil.example");
        let victim = did("did:web:victim.example");
        let victim_key = url(&victim, "key1");

        let doc = document(
            attacker,
            vec![VerificationMethod::Map(Box::new(map(
                victim_key.clone(),
                &victim,
            )))],
        );

        assert_eq!(
            doc.resolve_verification_method_url(&victim_key, VerificationRole::Authentication),
            None,
            "a document must not speak for an identifier it does not control"
        );
    }

    #[test]
    fn rejects_verification_method_entry_for_another_did() {
        let attacker = did("did:web:evil.example");
        let victim = did("did:web:victim.example");
        let victim_key = url(&victim, "key1");

        let mut doc = document(attacker, vec![VerificationMethod::Url(victim_key.clone())]);
        doc.verification_method = Some(vec![map(victim_key.clone(), &victim)]);

        assert_eq!(
            doc.resolve_verification_method_url(&victim_key, VerificationRole::Authentication),
            None
        );
    }

    #[test]
    fn verification_methods_yields_every_resolvable_entry_for_a_role() {
        let me = did("did:web:example.com");
        let one = url(&me, "key1");
        let two = url(&me, "key2");

        let mut doc = document(
            me.clone(),
            vec![
                VerificationMethod::Url(one.clone()),
                VerificationMethod::Url(two.clone()),
            ],
        );
        doc.verification_method = Some(vec![map(one.clone(), &me), map(two.clone(), &me)]);

        assert_eq!(
            doc.verification_methods(VerificationRole::Authentication)
                .collect::<Vec<_>>(),
            vec![&map(one, &me), &map(two, &me)]
        );
        assert_eq!(
            doc.verification_methods(VerificationRole::KeyAgreement)
                .count(),
            0
        );
    }

    #[test]
    fn verification_methods_skips_an_entry_for_another_did() {
        let attacker = did("did:web:evil.example");
        let victim = did("did:web:victim.example");
        let victim_key = url(&victim, "key1");

        let mut doc = document(attacker, vec![VerificationMethod::Url(victim_key.clone())]);
        doc.verification_method = Some(vec![map(victim_key, &victim)]);

        assert_eq!(
            doc.verification_methods(VerificationRole::Authentication)
                .count(),
            0,
            "a document must not present another identifier's key as its own"
        );
    }

    #[test]
    fn role_is_respected() {
        let me = did("did:web:example.com");
        let key = url(&me, "key1");

        let mut doc = document(me.clone(), vec![VerificationMethod::Url(key.clone())]);
        doc.verification_method = Some(vec![map(key.clone(), &me)]);

        assert!(
            doc.resolve_verification_method_url(&key, VerificationRole::Authentication)
                .is_some()
        );
        assert!(
            doc.resolve_verification_method_url(&key, VerificationRole::KeyAgreement)
                .is_none()
        );
    }
}
