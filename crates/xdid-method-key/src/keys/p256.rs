use jose_jwk::Jwk;
use p256::{
    SecretKey,
    ecdsa::{
        Signature,
        SigningKey,
        signature::Signer as _,
    },
    elliptic_curve::{
        rand_core::OsRng,
        sec1::{
            FromEncodedPoint,
            ToEncodedPoint,
        },
        zeroize::Zeroizing,
    },
    pkcs8::{
        DecodePrivateKey,
        EncodePrivateKey,
        LineEnding,
    },
};

use super::{
    DidKeyPair,
    KeyParser,
    Multicodec,
    PublicKey,
    Signer,
    WithMulticodec,
};
use crate::parser::ParseError;

/// Multicodec `p256-pub`, as an unsigned varint.
const CODE: &[u8] = &[0x80, 0x24];

#[derive(Clone)]
pub struct P256KeyPair(SecretKey);

impl DidKeyPair for P256KeyPair {
    fn generate() -> Self {
        let mut rng = OsRng;
        Self(SecretKey::random(&mut rng))
    }

    fn public(&self) -> impl PublicKey {
        P256PublicKey(self.0.public_key())
    }

    fn to_pkcs8_pem(&self) -> anyhow::Result<Zeroizing<String>> {
        Ok(self.0.to_pkcs8_pem(LineEnding::LF)?)
    }

    fn from_pkcs8_pem(pem: &str) -> anyhow::Result<Self> {
        Ok(Self(SecretKey::from_pkcs8_pem(pem)?))
    }
}

impl Signer for P256KeyPair {
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signing_key = SigningKey::from(&self.0);
        let sig: Signature = signing_key.try_sign(message)?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct P256PublicKey(p256::PublicKey);

impl PublicKey for P256PublicKey {
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
    fn parse(&self, public_key: &[u8]) -> Result<Box<dyn PublicKey>, ParseError> {
        let point =
            p256::EncodedPoint::from_bytes(public_key).map_err(|_| ParseError::InvalidPublicKey)?;
        let key = p256::PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or(ParseError::InvalidPublicKey)?;
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
    fn code(&self) -> &'static [u8] {
        CODE
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{
        Signature as EcdsaSignature,
        VerifyingKey,
        signature::Verifier,
    };

    use super::*;
    use crate::parser::DidKeyParser;

    #[test]
    fn test_display() {
        let did = P256KeyPair::generate().public().to_did();
        assert!(did.to_string().starts_with("did:key:zDn"));
    }

    #[test]
    fn test_jwk() {
        let _ = P256KeyPair::generate().public().to_jwk();
    }

    #[test]
    fn test_jwk_has_no_private_component() {
        let jwk = P256KeyPair::generate().public().to_jwk();
        let json = serde_json::to_string(&jwk).expect("serialization should succeed");

        assert!(!json.contains("\"d\""), "private scalar leaked into JWK");
    }

    #[test]
    fn test_parse() {
        let did = P256KeyPair::generate().public().to_did();
        DidKeyParser::default()
            .parse(&did)
            .expect("parse should succeed");
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
