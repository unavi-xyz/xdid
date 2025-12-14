use multibase::Base;
use smallvec::SmallVec;
use thiserror::Error;
use xdid_core::did::Did;

use crate::keys::{KeyParser, PublicKey};

pub struct DidKeyParser {
    parsers: SmallVec<[Box<dyn KeyParser>; 2]>,
}

impl Default for DidKeyParser {
    fn default() -> Self {
        #[allow(unused_mut)]
        let mut parsers = SmallVec::<[Box<dyn KeyParser>; 2]>::new();

        #[cfg(feature = "p256")]
        parsers.push(Box::new(crate::keys::p256::P256KeyParser));

        #[cfg(feature = "p384")]
        parsers.push(Box::new(crate::keys::p384::P384KeyParser));

        Self { parsers }
    }
}

impl DidKeyParser {
    pub fn parse(&self, did: &Did) -> Result<Box<dyn PublicKey>, ParseError> {
        let (base, inner) = multibase::decode(&did.method_id.0)?;
        debug_assert_eq!(base, Base::Base58Btc);

        for parser in &self.parsers {
            let code = parser.codec().code();
            if let Some(bytes) = inner.strip_prefix(code.as_slice()) {
                return parser.parse(bytes.to_vec());
            }
        }

        Err(ParseError::CodecNotSupported)
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("failed to decode multibase: {0}")]
    Decode(#[from] multibase::Error),
    #[error("codec not supported")]
    CodecNotSupported,
    #[error("invalid public key")]
    InvalidPublicKey,
}
