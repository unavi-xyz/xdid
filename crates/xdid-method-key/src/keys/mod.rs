use jose_jwk::Jwk;
use thiserror::Error;
use xdid_core::did::{
    Did,
    MethodId,
    MethodName,
};
use zeroize::Zeroizing;

/// Defines the key pair, public key and parser for one NIST curve.
///
/// The curves differ only in which crate they come from, their multicodec
/// prefix, and the DID prefix their keys encode to. Everything else was a
/// verbatim copy before this, and a third curve would have made three.
macro_rules! nist_curve {
    ($curve:ident, $pair:ident, $code:expr, $did_prefix:literal) => {
        use ::$curve::{
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
        use jose_jwk::{
            Jwk,
            Key,
            Parameters,
        };
        use $crate::{
            keys::{
                DidKeyPair,
                KeyParser,
                Multicodec,
                PemError,
                PublicKey,
                SignError,
                Signer,
            },
            parser::ParseError,
        };

        /// Multicodec prefix, as an unsigned varint.
        const CODE: &[u8] = $code;

        #[derive(Clone)]
        pub struct $pair(SecretKey);

        impl DidKeyPair for $pair {
            fn generate() -> Self {
                let mut rng = OsRng;
                Self(SecretKey::random(&mut rng))
            }

            fn public(&self) -> impl PublicKey {
                Public(self.0.public_key())
            }

            fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>, PemError> {
                self.0
                    .to_pkcs8_pem(LineEnding::LF)
                    .map_err(|e| PemError::Encode(e.to_string()))
            }

            fn from_pkcs8_pem(pem: &str) -> Result<Self, PemError> {
                SecretKey::from_pkcs8_pem(pem)
                    .map(Self)
                    .map_err(|e| PemError::Decode(e.to_string()))
            }
        }

        impl Signer for $pair {
            type Error = SignError;

            fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
                let signing_key = SigningKey::from(&self.0);
                let sig: Signature = signing_key.try_sign(message).map_err(SignError::new)?;

                Ok(sig.to_der().as_bytes().to_vec())
            }
        }

        #[derive(Clone, PartialEq, Eq)]
        struct Public(::$curve::PublicKey);

        impl PublicKey for Public {
            fn to_encoded_point_bytes(&self) -> Box<[u8]> {
                self.0.to_encoded_point(true).as_bytes().into()
            }

            fn to_jwk(&self) -> Jwk {
                Jwk {
                    key: Key::Ec((&self.0).into()),
                    prm: Parameters::default(),
                }
            }
        }

        impl Multicodec for Public {
            fn code(&self) -> &'static [u8] {
                CODE
            }
        }

        pub(crate) struct Parser;

        impl KeyParser for Parser {
            fn parse(&self, public_key: &[u8]) -> Result<Box<dyn PublicKey>, ParseError> {
                let point = ::$curve::EncodedPoint::from_bytes(public_key)
                    .map_err(|_| ParseError::InvalidPublicKey)?;

                let key = ::$curve::PublicKey::from_encoded_point(&point)
                    .into_option()
                    .ok_or(ParseError::InvalidPublicKey)?;

                Ok(Box::new(Public(key)))
            }
        }

        impl Multicodec for Parser {
            fn code(&self) -> &'static [u8] {
                CODE
            }
        }

        #[cfg(test)]
        mod tests {
            use ::$curve::ecdsa::{
                Signature as EcdsaSignature,
                VerifyingKey,
                signature::Verifier,
            };

            use super::*;

            #[test]
            fn test_display() {
                let did = $pair::generate().public().to_did();
                assert!(
                    did.to_string()
                        .starts_with(concat!("did:key:", $did_prefix))
                );
            }

            #[test]
            fn test_jwk_has_no_private_component() {
                let jwk = $pair::generate().public().to_jwk();
                let json = serde_json::to_string(&jwk).expect("serialization should succeed");

                assert!(!json.contains("\"d\""), "private scalar leaked into JWK");
            }

            #[test]
            fn test_sign_verify() {
                let pair = $pair::generate();

                let msg = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
                let signature = pair.sign(&msg).expect("signing should succeed");

                let verifying_key = VerifyingKey::from(pair.0.public_key());
                let sig = EcdsaSignature::from_der(&signature).expect("valid signature");
                verifying_key
                    .verify(&msg, &sig)
                    .expect("verification should succeed");
            }
        }
    };
}

#[cfg(feature = "p256")] pub mod p256;
#[cfg(feature = "p384")] pub mod p384;

/// Const-evaluated, so a name that is not `1*method-char` fails the build and
/// `to_did` carries no check of its own.
const METHOD: MethodName = MethodName::from_static(crate::NAME).unwrap();

/// Keeps the signing backend out of the public API, where its version would
/// otherwise be part of this crate's semver contract.
#[derive(Debug, Error)]
#[error("failed to sign: {0}")]
pub struct SignError(String);

impl SignError {
    #[must_use]
    pub fn new(detail: impl std::fmt::Display) -> Self {
        Self(detail.to_string())
    }
}

/// Keeps `pkcs8` out of the public API; see [`SignError`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PemError {
    #[error("failed to encode the key: {0}")]
    Encode(String),
    #[error("failed to decode the key: {0}")]
    Decode(String),
}

pub trait Signer {
    /// What a failed signature reports. An implementor outside this crate uses
    /// its own error rather than adopting one of ours.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Sign a message with the private key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

pub trait DidKeyPair: Signer + Sized {
    /// Generate a new pair of keys.
    fn generate() -> Self;

    fn public(&self) -> impl PublicKey;

    /// Export the key pair as a PKCS#8 PEM string.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails.
    fn to_pkcs8_pem(&self) -> Result<Zeroizing<String>, PemError>;

    /// Import a key pair from a PKCS#8 PEM string.
    ///
    /// The borrowed `pem` cannot be cleared from here; the caller owns it and
    /// is responsible for zeroizing it once the key has been imported.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is invalid or cannot be decoded.
    fn from_pkcs8_pem(pem: &str) -> Result<Self, PemError>;
}

pub trait PublicKey: Multicodec {
    /// The compressed SEC1 point, which is the encoding `did:key` is built
    /// from.
    fn to_encoded_point_bytes(&self) -> Box<[u8]>;
    fn to_jwk(&self) -> Jwk;

    fn to_did(&self) -> Did {
        let bytes = self.to_encoded_point_bytes();
        let code = self.code();

        let mut inner = Vec::with_capacity(code.len() + bytes.len());
        inner.extend_from_slice(code);
        inner.extend_from_slice(&bytes);

        Did {
            method_name: METHOD,
            method_id:   MethodId::from_base58btc(&inner),
        }
    }
}

pub trait Multicodec {
    /// The multicodec prefix, as an unsigned varint.
    fn code(&self) -> &'static [u8];
}

pub trait KeyParser: Multicodec {
    /// Parse a public key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid public key.
    fn parse(&self, public_key: &[u8]) -> Result<Box<dyn PublicKey>, crate::parser::ParseError>;
}
