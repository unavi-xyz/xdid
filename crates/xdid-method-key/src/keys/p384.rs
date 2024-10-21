use jose_jwk::Jwk;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p384::SecretKey;
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
        P384PublicKey(
            self.secret
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
    }
}

pub struct P384PublicKey(Vec<u8>);

impl PublicKey for P384PublicKey {
    fn public_key(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn to_jwk(&self) -> Jwk {
        todo!();
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
        Box::new(P384PublicKey(public_key))
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
    use crate::DidKey;

    use super::*;

    #[test]
    fn test_display() {
        let pair = P384KeyPair::generate().unwrap();
        let did = DidKey::new(pair.to_public()).to_did();
        let did_str = did.to_string();
        println!("{}", did_str);
        assert!(did_str.starts_with("did:key:z82"));
    }
}
