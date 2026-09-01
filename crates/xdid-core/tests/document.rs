use std::str::FromStr;

use serde_json::Value;
use xdid_core::{
    did::Did,
    did_url::{
        DidUrl,
        relative::{
            RelativeDidUrl,
            RelativeDidUrlPath,
        },
    },
    document::{
        Document,
        VerificationMethod,
        VerificationMethodMap,
    },
};

#[test]
fn test_document_serde() {
    const EXPECTED_RAW: &[u8] = include_bytes!("./document-expected.json");

    let did = Did::from_str("did:web:localhost%3A4000").expect("valid DID");

    let owner = DidUrl::new(did.clone(), None, None, Some("owner".into())).expect("valid DID URL");

    let doc = Document {
        context:               None,
        id:                    did.clone(),
        also_known_as:         None,
        assertion_method:      Some(vec![VerificationMethod::RelativeUrl(
            RelativeDidUrl::new(RelativeDidUrlPath::Empty, None, Some("owner".into()))
                .expect("valid relative DID URL"),
        )]),
        authentication:        None,
        capability_delegation: Some(vec![VerificationMethod::Url(
            DidUrl::new(
                did.clone(),
                None,
                Some("test-query".into()),
                Some("owner".into()),
            )
            .expect("valid DID URL"),
        )]),
        capability_invocation: None,
        controller:            None,
        key_agreement:         None,
        service:               None,
        verification_method:   Some(vec![VerificationMethodMap {
            id:                   owner,
            controller:           did,
            typ:                  "JsonWebKey2020".into(),
            public_key_multibase: None,
            public_key_jwk:       None,
        }]),
    };

    let doc_val = serde_json::to_value(&doc).expect("serialization should succeed");

    let expected_val: Value =
        serde_json::from_slice(EXPECTED_RAW).expect("deserialization should succeed");
    assert_eq!(doc_val, expected_val);

    let expected_doc: Document =
        serde_json::from_slice(EXPECTED_RAW).expect("deserialization should succeed");
    assert_eq!(doc, expected_doc);
}
