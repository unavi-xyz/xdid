use jose_jwk::Jwk;
use thiserror::Error;
use xdid_core::did::{
    Did,
    MethodId,
    MethodName,
};
use zeroize::Zeroizing;

#[cfg(feature = "p256")] pub mod p256;
#[cfg(feature = "p384")] pub mod p384;

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

pub trait PublicKey: WithMulticodec {
    /// The compressed SEC1 point, which is the encoding `did:key` is built
    /// from.
    fn to_encoded_point_bytes(&self) -> Box<[u8]>;
    fn to_jwk(&self) -> Jwk;

    fn to_did(&self) -> Did {
        let bytes = self.to_encoded_point_bytes();
        let code = self.codec().code();

        let mut inner = Vec::with_capacity(code.len() + bytes.len());
        inner.extend_from_slice(code);
        inner.extend_from_slice(&bytes);

        Did {
            method_name: MethodName::KEY,
            method_id:   MethodId::from_base58btc(&inner),
        }
    }
}

pub trait Multicodec {
    /// The multicodec prefix, as an unsigned varint.
    fn code(&self) -> &'static [u8];
}

pub trait WithMulticodec {
    fn codec(&self) -> Box<dyn Multicodec>;
}

pub trait KeyParser: WithMulticodec {
    /// Parse a public key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not represent a valid public key.
    fn parse(&self, public_key: &[u8]) -> Result<Box<dyn PublicKey>, crate::parser::ParseError>;
}
