use multibase::Base;
use smallvec::SmallVec;
use thiserror::Error;
use xdid_core::did::Did;

use crate::keys::{
    KeyParser,
    PublicKey,
};

pub struct DidKeyParser {
    parsers: SmallVec<[Box<dyn KeyParser>; 2]>,
}

impl Default for DidKeyParser {
    fn default() -> Self {
        #[cfg_attr(
            not(any(feature = "p256", feature = "p384")),
            expect(unused_mut, reason = "every parser is behind a feature")
        )]
        let mut parsers = SmallVec::<[Box<dyn KeyParser>; 2]>::new();

        #[cfg(feature = "p256")]
        parsers.push(Box::new(crate::keys::p256::P256KeyParser));

        #[cfg(feature = "p384")]
        parsers.push(Box::new(crate::keys::p384::P384KeyParser));

        Self { parsers }
    }
}

impl DidKeyParser {
    /// Parse the public key out of a `did:key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID is not a canonically encoded `did:key` for a
    /// supported curve.
    pub fn parse(&self, did: &Did) -> Result<Box<dyn PublicKey>, ParseError> {
        let (base, inner) = multibase::decode(did.method_id.as_str())?;

        // did:key fixes the encoding at base58btc. Accepting any other
        // multibase would give every key an unlimited supply of
        // distinct DID strings.
        if base != Base::Base58Btc {
            return Err(ParseError::NotBase58Btc);
        }

        for parser in &self.parsers {
            let code = parser.codec().code();

            if let Some(bytes) = inner.strip_prefix(code) {
                let key = parser.parse(bytes)?;

                // Re-deriving the DID rejects the remaining non-canonical
                // encodings of the same key, notably uncompressed SEC1 points.
                if key.to_did() != *did {
                    return Err(ParseError::NotCanonical);
                }

                return Ok(key);
            }
        }

        Err(ParseError::CodecNotSupported)
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("failed to decode multibase: {0}")]
    Decode(#[from] multibase::Error),
    #[error("did:key must be encoded as base58btc")]
    NotBase58Btc,
    #[error("key is not in its canonical encoding")]
    NotCanonical,
    #[error("codec not supported")]
    CodecNotSupported,
    #[error("invalid public key")]
    InvalidPublicKey,
}

#[cfg(all(test, feature = "p256"))]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::keys::{
        DidKeyPair,
        p256::P256KeyPair,
    };

    fn generated() -> (Did, Vec<u8>) {
        let did = P256KeyPair::generate().public().to_did();
        let (_, bytes) = multibase::decode(did.method_id.as_str()).expect("valid multibase");
        (did, bytes)
    }

    #[test]
    fn accepts_canonical() {
        let (did, _) = generated();
        DidKeyParser::default()
            .parse(&did)
            .expect("canonical did:key should parse");
    }

    #[test]
    fn rejects_other_multibase_encodings() {
        let (_, bytes) = generated();
        let parser = DidKeyParser::default();

        for base in [Base::Base64Url, Base::Base16Lower, Base::Base32Lower] {
            let did = Did::from_str(&format!("did:key:{}", multibase::encode(base, &bytes)))
                .expect("valid DID syntax");

            assert!(
                matches!(parser.parse(&did), Err(ParseError::NotBase58Btc)),
                "{base:?} must not resolve to the same key as base58btc"
            );
        }
    }

    #[test]
    fn rejects_uncompressed_point() {
        use p256::elliptic_curve::sec1::{
            FromEncodedPoint,
            ToEncodedPoint,
        };

        let (canonical, inner) = generated();

        let point = p256::EncodedPoint::from_bytes(&inner[2..]).expect("compressed point");
        let key = p256::PublicKey::from_encoded_point(&point)
            .into_option()
            .expect("valid key");

        let mut uncompressed = inner[..2].to_vec();
        uncompressed.extend_from_slice(key.to_encoded_point(false).as_bytes());

        let did = Did::from_str(&format!(
            "did:key:{}",
            multibase::encode(Base::Base58Btc, &uncompressed)
        ))
        .expect("valid DID syntax");

        assert_ne!(did, canonical);
        assert!(matches!(
            DidKeyParser::default().parse(&did),
            Err(ParseError::NotCanonical)
        ));
    }
}
