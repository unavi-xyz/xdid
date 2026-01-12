use jose_jwk::Jwk;
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::SignerMut},
    elliptic_curve::{
        rand_core::OsRng,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        zeroize::Zeroizing,
    },
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};

use super::{DidKeyPair, KeyParser, Multicodec, PublicKey, Signer, WithMulticodec};

#[derive(Clone, PartialEq, Eq)]
pub struct P256KeyPair(SecretKey);

impl DidKeyPair for P256KeyPair {
    fn generate() -> Self {
        let mut rng = OsRng;
        let secret = SecretKey::random(&mut rng);
        Self(secret)
    }

    fn public(&self) -> impl PublicKey {
        P256PublicKey(self.0.public_key())
    }

    fn to_pkcs8_pem(&self) -> anyhow::Result<Zeroizing<String>> {
        let pem = self.0.to_pkcs8_pem(LineEnding::LF)?;
        Ok(pem)
    }
    fn from_pkcs8_pem(pem: &str) -> anyhow::Result<Self> {
        let key = SecretKey::from_pkcs8_pem(pem)?;
        Ok(Self(key))
    }
}

impl Signer for P256KeyPair {
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut signing_key = SigningKey::from(&self.0);
        let sig: Signature = signing_key.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct P256PublicKey(p256::PublicKey);

impl PublicKey for P256PublicKey {
    fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.0.to_sec1_bytes()
    }
    fn to_encoded_point_bytes(&self) -> Box<[u8]> {
        self.0.to_encoded_point(true).as_bytes().into()
    }

    fn to_jwk(&self) -> Jwk {
        let jwk_str = self.0.to_jwk_string();
        serde_json::from_str(&jwk_str).expect("p256 crate guarantees valid JWK")
    }
}

impl WithMulticodec for P256PublicKey {
    fn codec(&self) -> Box<dyn Multicodec> {
        Box::new(P256Codec)
    }
}

pub(crate) struct P256KeyParser;

impl KeyParser for P256KeyParser {
    fn parse(&self, public_key: Vec<u8>) -> Result<Box<dyn PublicKey>, crate::parser::ParseError> {
        let point = p256::EncodedPoint::from_bytes(public_key)
            .map_err(|_| crate::parser::ParseError::InvalidPublicKey)?;
        let key = p256::PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or(crate::parser::ParseError::InvalidPublicKey)?;
        Ok(Box::new(P256PublicKey(key)))
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
    use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey, signature::Verifier};

    use crate::parser::DidKeyParser;

    use super::*;

    #[test]
    fn test_display() {
        let pair = P256KeyPair::generate();
        let did = pair.public().to_did();

        let did_str = did.to_string();
        println!("{did_str}");
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
        let _ = parser.parse(&did).expect("parse should succeed");
    }

    #[test]
    fn test_sign_verify() {
        let pair = P256KeyPair::generate();

        let msg = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
        let signature = pair.sign(&msg).expect("signing should succeed");

        let verifying_key = VerifyingKey::from(pair.0.public_key());
        let sig = EcdsaSignature::from_der(&signature).expect("valid signature");
        verifying_key
            .verify(&msg, &sig)
            .expect("verification should succeed");
    }
}
