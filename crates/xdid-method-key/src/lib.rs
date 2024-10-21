//! Implementation of [did:key](https://w3c-ccg.github.io/did-method-key/), using [xdid](https://github.com/unavi-xyz/xdid).

use std::fmt::Display;

use multibase::Base;
use xdid_core::Method;

pub mod keys;

const PREFIX: &str = "key";

pub struct DidKey {
    key: Box<dyn keys::Key>,
}

impl Display for DidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_bytes = self.key.public_key();

        let mut buffer = unsigned_varint::encode::u64_buffer();
        let code = unsigned_varint::encode::u64(self.key.public_code(), &mut buffer);

        let mut inner = Vec::with_capacity(code.len() + key_bytes.len());
        inner.extend(code);
        inner.extend(key_bytes);

        let id = multibase::encode(Base::Base58Btc, inner);
        write!(f, "did:{}:{}", PREFIX, id)
    }
}

impl Method for DidKey {}
