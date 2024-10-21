use jose_jwk::Jwk;
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use rand::rngs::OsRng;

use super::{KeyParser, Multicodec, PublicKey, WithMulticodec};

pub struct P256KeyPair {
    secret: SecretKey,
}

impl P256KeyPair {
    pub fn generate() -> Result<Self, ring::error::Unspecified> {
        let mut rng = OsRng;
        let secret = SecretKey::random(&mut rng);
        Ok(Self { secret })
    }

    pub fn to_public(&self) -> P256PublicKey {
        P256PublicKey(
            self.secret
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
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
