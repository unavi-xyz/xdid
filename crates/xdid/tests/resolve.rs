mod common;

use std::str::FromStr;

use common::{
    Reply,
    document_body,
    local_config,
    resolver_with,
    serve,
};
use xdid::{
    core::{
        ResolutionError,
        did::Did,
        document::Document,
    },
    method::{
        key::{
            DidKeyPair,
            PublicKey,
            p256::P256KeyPair,
        },
        web::Config,
    },
    resolver::DidResolver,
};

#[tokio::test]
async fn resolves_a_did_key_offline() {
    let did = P256KeyPair::generate().public().to_did();

    let document = DidResolver::new()
        .expect("resolver construction should succeed")
        .resolve(&did)
        .await
        .expect("resolution should succeed");

    assert_eq!(document.id, did);
}

#[tokio::test]
async fn resolves_a_did_web() {
    let did = serve(|did| Reply::ok(document_body(did))).await;

    let document = resolver_with(local_config())
        .resolve(&did)
        .await
        .expect("resolution should succeed");

    assert_eq!(document.id, did);
}

#[tokio::test]
async fn rejects_a_document_claiming_another_did() {
    let did = serve(|_| {
        let other = Did::from_str("did:web:victim.example").expect("valid DID");
        Reply::ok(document_body(&other))
    })
    .await;

    let err = resolver_with(local_config())
        .resolve(&did)
        .await
        .expect_err("a document claiming another DID must be rejected");

    assert!(matches!(err, ResolutionError::DocumentMismatch), "{err:?}");
}

#[tokio::test]
async fn rejects_an_oversized_document() {
    let did = serve(|did| {
        let mut doc = Document::new(did.clone());
        doc.also_known_as = Some(vec!["x".repeat(64 * 1024)]);
        Reply::ok(serde_json::to_string(&doc).expect("serialization should succeed"))
    })
    .await;

    let err = resolver_with(Config {
        max_document_bytes: 1024,
        ..local_config()
    })
    .resolve(&did)
    .await
    .expect_err("an oversized document must be rejected");

    assert!(matches!(err, ResolutionError::DocumentTooLarge), "{err:?}");
}

#[tokio::test]
async fn rejects_a_redirect() {
    let did = serve(|_| Reply::redirect("https://evil.example/.well-known/did.json")).await;

    let err = resolver_with(local_config())
        .resolve(&did)
        .await
        .expect_err("a redirect must not be followed");

    let ResolutionError::Transport(detail) = err else {
        panic!("a refused redirect must not be reported as a malformed document: {err:?}");
    };

    assert!(detail.contains("302"), "{detail}");
}

/// The document is served, and served correctly. Refusing it is a property of
/// the target, not of the response.
#[tokio::test]
async fn rejects_a_plaintext_localhost_target_by_default() {
    let did = serve(|did| Reply::ok(document_body(did))).await;

    let err = resolver_with(Config::default())
        .resolve(&did)
        .await
        .expect_err("a loopback target must be rejected");

    assert!(matches!(err, ResolutionError::TargetNotAllowed), "{err:?}");
}

#[tokio::test]
async fn rejects_a_restricted_literal_target() {
    let resolver = resolver_with(Config::default());

    for did in [
        "did:web:127.0.0.1",
        "did:web:169.254.169.254",
        "did:web:10.0.0.1",
    ] {
        let did = Did::from_str(did).expect("valid DID");

        let err = resolver
            .resolve(&did)
            .await
            .expect_err("a restricted target must be rejected");

        assert!(matches!(err, ResolutionError::TargetNotAllowed), "{err:?}");
    }
}
