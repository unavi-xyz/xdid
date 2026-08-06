use std::str::FromStr;

use jose_jwk::Jwk;
use multibase::Base;
use xdid_core::did::{
    Did,
    MethodId,
    MethodName,
};
use zeroize::Zeroizing;

use crate::NAME;

#[cfg(feature = "p256")] pub mod p256;
#[cfg(feature = "p384")] pub mod p384;

pub trait Signer {
    /// Sign a message with the private key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>>;
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
    fn to_pkcs8_pem(&self) -> anyhow::Result<Zeroizing<String>>;

    /// Import a key pair from a PKCS#8 PEM string.
    ///
    /// The borrowed `pem` cannot be cleared from here; the caller owns it and
    /// is responsible for zeroizing it once the key has been imported.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM is invalid or cannot be decoded.
    fn from_pkcs8_pem(pem: &str) -> anyhow::Result<Self>;
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
            method_name: MethodName::from_str(NAME).expect("method name is a valid constant"),
            method_id:   MethodId::from_str(&multibase::encode(Base::Base58Btc, inner))
                .expect("base58btc alphabet is a subset of idchar"),
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
