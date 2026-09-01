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
    methods: SmallVec<[Box<dyn Method>; 2]>,
}

impl DidResolver {
    /// Creates a resolver over `methods`, tried in the order given.
    pub fn with_methods(methods: impl IntoIterator<Item = Box<dyn Method>>) -> Self {
        Self {
            methods: methods.into_iter().collect(),
        }
    }

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
                return method.resolve(did).await;
            }
        }

        Err(ResolutionError::UnsupportedMethod)
    }
}
