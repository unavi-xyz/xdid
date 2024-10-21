use jose_jwk::Jwk;
use p521::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::DecodePublicKey, SecretKey};
use rand::rngs::OsRng;

use super::{KeyParser, Multicodec, PublicKey, WithMulticodec};

pub struct P521KeyPair {
    secret: SecretKey,
}

impl P521KeyPair {
    pub fn generate() -> Result<Self, ring::error::Unspecified> {
        let mut rng = OsRng;
        let secret = SecretKey::random(&mut rng);
        Ok(Self { secret })
    }

    pub fn to_public(&self) -> P521PublicKey {
        P521PublicKey(self.secret.public_key())
    }
}

pub struct P521PublicKey(p521::PublicKey);

impl PublicKey for P521PublicKey {
    fn public_key(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
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

pub struct P521KeyParser;

impl KeyParser for P521KeyParser {
    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey> {
        let key = p521::PublicKey::from_public_key_der(&public_key).unwrap();
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
    use crate::DidKey;

    use super::*;

    #[test]
    fn test_display() {
        let pair = P521KeyPair::generate().unwrap();
        let did = DidKey::new(pair.to_public()).to_did();
        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:z2J9"));
    }

    #[test]
    fn test_jwk() {
        let pair = P521KeyPair::generate().unwrap();
        let _ = pair.to_public().to_jwk();
    }
}
