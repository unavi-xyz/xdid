use jose_jwk::Jwk;
use p521::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    SecretKey,
};
use rand::rngs::OsRng;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING},
};

use super::{DidKeyPair, KeyParser, Multicodec, PublicKey, SignError, WithMulticodec};

pub struct P521KeyPair {
    secret: SecretKey,
}

impl DidKeyPair for P521KeyPair {
    fn generate() -> Self {
        let mut rng = OsRng;
        let secret = SecretKey::random(&mut rng);
        Self { secret }
    }

    fn public(&self) -> impl PublicKey {
        P521PublicKey(self.secret.public_key())
    }
    fn public_bytes(&self) -> Box<[u8]> {
        self.secret.public_key().to_sec1_bytes()
    }
    fn secret_bytes(&self) -> Box<[u8]> {
        self.secret.to_bytes().to_vec().into()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let rng = SystemRandom::new();

        let signer = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P384_SHA384_ASN1_SIGNING,
            &self.secret_bytes(),
            &self.public_bytes(),
            &rng,
        )
        .unwrap();

        signer
            .sign(&rng, message)
            .map(|v| v.as_ref().to_vec())
            .map_err(|_| SignError::SigningFailed)
    }
}

struct P521PublicKey(p521::PublicKey);

impl PublicKey for P521PublicKey {
    fn as_did_bytes(&self) -> Box<[u8]> {
        self.0.to_encoded_point(true).as_bytes().into()
    }

    fn to_jwk(&self) -> Jwk {
        let jwk_str = self.0.to_jwk_string();
        serde_json::from_str(&jwk_str).unwrap()
    }
}

impl WithMulticodec for P521PublicKey {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(P521Codec)
    }
}

pub(crate) struct P521KeyParser;

impl KeyParser for P521KeyParser {
    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey> {
        let point = p521::EncodedPoint::from_bytes(public_key).unwrap();
        let key = p521::PublicKey::from_encoded_point(&point).unwrap();
        Box::new(P521PublicKey(key))
    }
}

impl WithMulticodec for P521KeyParser {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(P521Codec)
    }
}

struct P521Codec;

impl Multicodec for P521Codec {
    fn code_u64(&self) -> u64 {
        0x1202
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::DidKeyParser;

    use super::*;

    #[test]
    fn test_display() {
        let pair = P521KeyPair::generate();
        let did = pair.public().to_did();

        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:z2J9"));
    }

    #[test]
    fn test_jwk() {
        let pair = P521KeyPair::generate();
        let _ = pair.public().to_jwk();
    }

    #[test]
    fn test_parse() {
        let pair = P521KeyPair::generate();
        let did = pair.public().to_did();

        let parser = DidKeyParser::default();
        let _ = parser.parse(&did).unwrap();
    }
}
