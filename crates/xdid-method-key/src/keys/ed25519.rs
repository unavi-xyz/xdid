use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};

use super::Key;

pub struct Ed25519Key {
    key: Ed25519KeyPair,
}

impl Ed25519Key {
    /// Generates a new key.
    pub fn generate() -> Result<Self, ring::error::Unspecified> {
        let rng = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        Ok(Self { key })
    }
}

impl Key for Ed25519Key {
    fn public_code(&self) -> u64 {
        0xed
    }

    fn public_key(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::DidKey;

    use super::*;

    #[test]
    fn test_display() {
        let key = Ed25519Key::generate().unwrap();
        let did = DidKey { key: Box::new(key) };
        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:z6Mk"));
    }
}
