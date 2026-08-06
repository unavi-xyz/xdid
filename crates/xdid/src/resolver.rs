use smallvec::SmallVec;
use thiserror::Error;
use xdid_core::{
    Method,
    ResolutionError,
    did::Did,
    document::Document,
};

/// Resolves DIDs using a set of provided methods.
pub struct DidResolver {
    pub methods: SmallVec<[Box<dyn Method>; 2]>,
}

impl DidResolver {
    /// Creates a new resolver with all enabled methods.
    ///
    /// # Errors
    ///
    /// Returns an error if a method fails to initialize.
    pub fn new() -> Result<Self, MethodError> {
        #[cfg_attr(
            not(any(feature = "did-key", feature = "did-web")),
            expect(unused_mut, reason = "every method is behind a feature")
        )]
        let mut methods = SmallVec::<[Box<dyn Method>; 2]>::new();

        #[cfg(feature = "did-key")]
        methods.push(Box::new(xdid_method_key::MethodDidKey));

        #[cfg(feature = "did-web")]
        methods.push(Box::new(xdid_method_web::MethodDidWeb::new()?));

        Ok(Self { methods })
    }
}

#[derive(Error, Debug)]
pub enum MethodError {
    #[cfg(feature = "did-web")]
    #[error("failed to construct did:web resolver: {0}")]
    DidWeb(#[from] xdid_method_web::ClientError),
}

impl DidResolver {
    /// Resolve a DID to its document.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID method is unsupported or resolution fails.
    pub async fn resolve(&self, did: &Did) -> Result<Document, ResolutionError> {
        for method in &self.methods {
            if method.method_name() == did.method_name.as_str() {
                return method.resolve(did.clone()).await;
            }
        }

        Err(ResolutionError::UnsupportedMethod)
    }
}

#[cfg(all(test, feature = "did-key"))]
mod did_key_tests {
    use xdid_method_key::keys::{
        DidKeyPair,
        PublicKey,
        p256::P256KeyPair,
    };

    use super::*;

    #[tokio::test]
    async fn test_resolve_did_key() {
        let did = P256KeyPair::generate().public().to_did();
        let resolver = DidResolver::new().expect("resolver construction should succeed");
        let document = resolver
            .resolve(&did)
            .await
            .expect("resolution should succeed");
        assert_eq!(document.id, did);
    }
}

#[cfg(all(test, feature = "did-web"))]
mod did_web_tests {
    use std::{
        net::SocketAddr,
        str::FromStr,
        sync::Arc,
    };

    use hyper::{
        Response,
        server::conn::http1::Builder,
        service::service_fn,
    };
    use hyper_util::rt::TokioIo;
    use smallvec::smallvec;
    use tokio::net::TcpListener;
    use xdid_method_web::{
        Config,
        MethodDidWeb,
    };

    use super::*;

    fn resolver_with(config: Config) -> DidResolver {
        let method = MethodDidWeb::with_config(config).expect("resolver construction");
        DidResolver {
            methods: smallvec![Box::new(method) as Box<dyn Method>],
        }
    }

    fn local_config() -> Config {
        Config {
            allow_local: true,
            ..Config::default()
        }
    }

    fn document_for(did: &Did) -> Document {
        Document {
            context:               None,
            id:                    did.clone(),
            also_known_as:         None,
            assertion_method:      None,
            authentication:        None,
            capability_delegation: None,
            capability_invocation: None,
            controller:            None,
            key_agreement:         None,
            service:               None,
            verification_method:   None,
        }
    }

    async fn serve(make_body: impl FnOnce(&Did) -> String) -> Did {
        let port = port_check::free_local_port().expect("free port should be available");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr).await.expect("listener should bind");

        let did = Did::from_str(&format!("did:web:localhost%3A{port}")).expect("valid DID");
        let data = Arc::new(make_body(&did));

        let handler = move |_| {
            let data = data.clone();
            async move { Ok::<_, hyper::Error>(Response::new(data.to_string())) }
        };

        tokio::spawn(async move {
            loop {
                let (stream, _) = listener
                    .accept()
                    .await
                    .expect("listener should accept connections");
                let io = TokioIo::new(stream);

                if let Err(e) = Builder::new()
                    .serve_connection(io, service_fn(&handler))
                    .await
                {
                    panic!("Error serving connection: {e:?}");
                }
            }
        });

        did
    }

    #[tokio::test]
    async fn test_resolve_did_web() {
        let did = serve(|did| {
            serde_json::to_string(&document_for(did)).expect("serialization should succeed")
        })
        .await;

        let document = resolver_with(local_config())
            .resolve(&did)
            .await
            .expect("resolution should succeed");

        assert_eq!(document.id, did);
    }

    #[tokio::test]
    async fn test_rejects_document_id_mismatch() {
        let did = serve(|_| {
            let other = Did::from_str("did:web:victim.example").expect("valid DID");
            serde_json::to_string(&document_for(&other)).expect("serialization should succeed")
        })
        .await;

        let err = resolver_with(local_config())
            .resolve(&did)
            .await
            .expect_err("a document claiming another DID must be rejected");

        assert!(matches!(err, ResolutionError::DocumentMismatch), "{err:?}");
    }

    #[tokio::test]
    async fn test_rejects_oversized_document() {
        let did = serve(|did| {
            let mut doc = document_for(did);
            doc.also_known_as = Some(vec!["x".repeat(64 * 1024)]);
            serde_json::to_string(&doc).expect("serialization should succeed")
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
    async fn test_rejects_restricted_target() {
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
}
