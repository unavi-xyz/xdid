use jose_jwk::Jwk;
use p256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    SecretKey,
};
use rand::rngs::OsRng;

use super::{KeyPair, KeyParser, Multicodec, PublicKey, WithMulticodec};

pub struct P256KeyPair {
    secret: SecretKey,
}

impl KeyPair for P256KeyPair {
    fn generate() -> Self {
        let mut rng = OsRng;
        let secret = SecretKey::random(&mut rng);
        Self { secret }
    }

    fn public(&self) -> impl PublicKey {
        P256PublicKey(self.secret.public_key())
    }
    fn public_bytes(&self) -> Box<[u8]> {
        self.secret.public_key().to_sec1_bytes()
    }
    fn secret_bytes(&self) -> Box<[u8]> {
        self.secret.to_bytes().to_vec().into()
    }
}

struct P256PublicKey(p256::PublicKey);

impl PublicKey for P256PublicKey {
    fn bytes(&self) -> Box<[u8]> {
        self.0.to_encoded_point(true).as_bytes().into()
    }

    fn to_jwk(&self) -> Jwk {
        let jwk_str = self.0.to_jwk_string();
        serde_json::from_str(&jwk_str).unwrap()
    }
}

impl WithMulticodec for P256PublicKey {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(P256Codec)
    }
}

pub(crate) struct P256KeyParser;

impl KeyParser for P256KeyParser {
    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey> {
        let point = p256::EncodedPoint::from_bytes(public_key).unwrap();
        let key = p256::PublicKey::from_encoded_point(&point).unwrap();
        Box::new(P256PublicKey(key))
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
    use crate::parser::DidKeyParser;

    use super::*;

    #[test]
    fn test_display() {
        let pair = P256KeyPair::generate();
        let did = pair.public().to_did();

        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:zDn"));
    }

    #[test]
    fn test_jwk() {
        let pair = P256KeyPair::generate();
        let _ = pair.public().to_jwk();
    }

    #[test]
    fn test_parse() {
        let pair = P256KeyPair::generate();
        let did = pair.public().to_did();

        let parser = DidKeyParser::default();
        let _ = parser.parse(&did).unwrap();
    }
}
