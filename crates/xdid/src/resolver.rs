use xdid_core::{did::Did, document::Document, Method, ResolutionError};

/// Resolves DIDs using a set of provided methods.
pub struct DidResolver {
    pub methods: Vec<Box<dyn Method>>,
}

impl Default for DidResolver {
    fn default() -> Self {
        let mut methods = Vec::<Box<dyn Method>>::new();

        #[cfg(feature = "did-key")]
        methods.push(Box::new(xdid_method_key::MethodDidKey));

        Self { methods }
    }
}

impl DidResolver {
    pub async fn resolve(&self, did: &Did) -> Result<Document, ResolutionError> {
        for method in self.methods.iter() {
            if method.method_name() == did.method_name.0 {
                return method.resolve(did.clone()).await;
            }
        }

        Err(ResolutionError::UnsupportedMethod)
    }
}
