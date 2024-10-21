use jose_jwk::Jwk;
use p256::pkcs8::DecodePublicKey;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};

use super::{KeyParser, Multicodec, PublicKey, WithMulticodec};

pub struct P256KeyPair {
    pair: EcdsaKeyPair,
}

static ALG: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_ASN1_SIGNING;

impl P256KeyPair {
    pub fn generate() -> Result<Self, ring::error::Unspecified> {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(ALG, &rng)?;
        let pair = EcdsaKeyPair::from_pkcs8(ALG, document.as_ref(), &rng).unwrap();
        Ok(Self { pair })
    }

    pub fn to_public(&self) -> P256PublicKey {
        let bytes = self.pair.public_key().as_ref();
        let compressed = p256::PublicKey::from_public_key_der(bytes).unwrap();
        P256PublicKey(compressed.to_sec1_bytes().to_vec())
    }
}

pub struct P256PublicKey(Vec<u8>);

impl PublicKey for P256PublicKey {
    fn public_key(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn to_jwk(&self) -> Jwk {
        todo!();
    }
}

impl WithMulticodec for P256PublicKey {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(P256Codec)
    }
}

pub struct P256KeyParser;

impl KeyParser for P256KeyParser {
    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey> {
        Box::new(P256PublicKey(public_key))
    }
}

impl WithMulticodec for P256KeyParser {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(P256Codec)
    }
}

struct P256Codec;

impl Multicodec for P256Codec {
    fn code_u64(&self) -> u64 {
        0x1200
    }
}

#[cfg(test)]
mod tests {
    use crate::DidKey;

    use super::*;

    #[test]
    fn test_display() {
        let pair = P256KeyPair::generate().unwrap();
        let did = DidKey::new(pair.to_public()).to_did();
        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:zDn"));
    }
}
