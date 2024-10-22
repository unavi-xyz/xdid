use jose_jwk::Jwk;
use ring::{rand::SystemRandom, signature::KeyPair};

use super::{KeyParser, Multicodec, PublicKey, WithMulticodec};

pub struct Ed25519KeyPair {
    pair: ring::signature::Ed25519KeyPair,
}

impl Ed25519KeyPair {
    pub fn generate() -> Result<Self, ring::error::Unspecified> {
        let rng = SystemRandom::new();
        let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        Ok(Self { pair })
    }

    pub fn public(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.pair.public_key().as_ref().to_owned())
    }
}

pub struct Ed25519PublicKey(Vec<u8>);

impl PublicKey for Ed25519PublicKey {
    fn public_key(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn to_jwk(&self) -> Jwk {
        todo!("ed25519 currently unimplemented in jose_jwk");
    }
}

impl WithMulticodec for Ed25519PublicKey {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(Ed25519Codec)
    }
}

pub struct Ed25519KeyParser;

impl KeyParser for Ed25519KeyParser {
    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey> {
        Box::new(Ed25519PublicKey(public_key))
    }
}

impl WithMulticodec for Ed25519KeyParser {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(Ed25519Codec)
    }
}

struct Ed25519Codec;

impl Multicodec for Ed25519Codec {
    fn code_u64(&self) -> u64 {
        0xed
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_display() {
        let pair = Ed25519KeyPair::generate().unwrap();
        let did = pair.public().to_did();
        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:z6Mk"));
    }
}
