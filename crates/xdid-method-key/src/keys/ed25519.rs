use jose_jwk::Jwk;
use ring::{rand::SystemRandom, signature::KeyPair};

use super::{DidKeyPair, KeyParser, Multicodec, PublicKey, SignError, Signer, WithMulticodec};

pub struct Ed25519KeyPair {
    pair: ring::signature::Ed25519KeyPair,
}

impl DidKeyPair for Ed25519KeyPair {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        Self { pair }
    }

    fn public(&self) -> impl PublicKey {
        Ed25519PublicKey(self.pair.public_key().as_ref().to_owned())
    }
    fn public_bytes(&self) -> Box<[u8]> {
        self.pair.public_key().as_ref().to_vec().into()
    }
    fn secret_bytes(&self) -> Box<[u8]> {
        todo!();
    }
}

impl Signer for Ed25519KeyPair {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.pair.sign(message).as_ref().to_vec())
    }
}

pub struct Ed25519PublicKey(Vec<u8>);

impl PublicKey for Ed25519PublicKey {
    fn as_did_bytes(&self) -> Box<[u8]> {
        self.0.clone().into()
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
        let pair = Ed25519KeyPair::generate();
        let did = pair.public().to_did();
        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:z6Mk"));
    }
}
