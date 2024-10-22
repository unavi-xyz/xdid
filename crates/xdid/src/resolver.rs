use xdid_core::{did::Did, document::Document, Method, ResolutionError};

/// Resolves DIDs using a set of provided methods.
pub struct DidResolver {
    pub methods: Vec<Box<dyn Method>>,
}

impl Default for DidResolver {
    fn default() -> Self {
        let methods: Vec<Box<dyn Method>> = vec![
            #[cfg(feature = "did-key")]
            Box::new(xdid_method_key::MethodDidKey),
        ];

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

#[cfg(test)]
mod tests {
    use xdid_method_key::{p256::P256KeyPair, KeyPair, PublicKey};

    use super::*;

    #[tokio::test]
    async fn test_resolve_did_key() {
        let did = P256KeyPair::generate().public().to_did();
        let resolver = DidResolver::default();
        let document = resolver.resolve(&did).await.unwrap();
        assert_eq!(document.id, did);
    }
}
