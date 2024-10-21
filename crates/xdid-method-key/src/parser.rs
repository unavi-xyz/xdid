use multibase::Base;
use thiserror::Error;
use xdid_core::did::Did;

use crate::{keys::KeyParser, DidKey};

pub struct DidKeyParser {
    parsers: Vec<Box<dyn KeyParser>>,
}

impl Default for DidKeyParser {
    fn default() -> Self {
        let mut parsers = Vec::<Box<dyn KeyParser>>::new();

        #[cfg(feature = "ed25519")]
        parsers.push(Box::new(crate::keys::ed25519::Ed25519KeyParser));

        Self { parsers }
    }
}

impl DidKeyParser {
    pub fn parse(&self, did: &Did) -> Result<DidKey, ParseError> {
        let (base, inner) = multibase::decode(&did.method_id.0)?;
        debug_assert_eq!(base, Base::Base58Btc);

        for parser in self.parsers.iter() {
            if inner.starts_with(&parser.code()) {
                return Ok(DidKey {
                    key: parser.parse(inner),
                });
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
}
