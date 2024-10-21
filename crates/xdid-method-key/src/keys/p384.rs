use jose_jwk::Jwk;
use p384::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    SecretKey,
};
use rand::rngs::OsRng;

use super::{KeyParser, Multicodec, PublicKey, WithMulticodec};

pub struct P384KeyPair {
    secret: SecretKey,
}

impl P384KeyPair {
    pub fn generate() -> Result<Self, ring::error::Unspecified> {
        let mut rng = OsRng;
        let secret = SecretKey::random(&mut rng);
        Ok(Self { secret })
    }

    pub fn to_public(&self) -> P384PublicKey {
        P384PublicKey(self.secret.public_key())
    }
}

pub struct P384PublicKey(p384::PublicKey);

impl PublicKey for P384PublicKey {
    fn public_key(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    fn to_jwk(&self) -> Jwk {
        let jwk_str = self.0.to_jwk_string();
        serde_json::from_str(&jwk_str).unwrap()
    }
}

impl WithMulticodec for P384PublicKey {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(P384Codec)
    }
}

pub struct P384KeyParser;

impl KeyParser for P384KeyParser {
    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey> {
        let point = p384::EncodedPoint::from_bytes(public_key).unwrap();
        let key = p384::PublicKey::from_encoded_point(&point).unwrap();
        Box::new(P384PublicKey(key))
    }
}

impl WithMulticodec for P384KeyParser {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(P384Codec)
    }
}

struct P384Codec;

impl Multicodec for P384Codec {
    fn code_u64(&self) -> u64 {
        0x1201
    }
}

#[cfg(test)]
mod tests {
    use crate::{parser::DidKeyParser, DidKey};

    use super::*;

    #[test]
    fn test_display() {
        let pair = P384KeyPair::generate().unwrap();
        let did = DidKey::new(pair.to_public()).to_did();

        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:z82"));
    }

    #[test]
    fn test_jwk() {
        let pair = P384KeyPair::generate().unwrap();
        let _ = pair.to_public().to_jwk();
    }

    #[test]
    fn test_parse() {
        let pair = P384KeyPair::generate().unwrap();
        let did = DidKey::new(pair.to_public()).to_did();

        let parser = DidKeyParser::default();
        let _ = parser.parse(&did).unwrap();
    }
}
