use jose_jwk::Jwk;
use multibase::Base;
use xdid_core::did::{Did, MethodId, MethodName};

use crate::NAME;

#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "p384")]
pub mod p384;
#[cfg(feature = "p521")]
pub mod p521;

pub trait KeyPair {
    fn generate() -> Self;

    fn public(&self) -> impl PublicKey;
    fn public_bytes(&self) -> Box<[u8]>;
    fn secret_bytes(&self) -> Box<[u8]>;
}

pub trait PublicKey: WithMulticodec {
    fn bytes(&self) -> Box<[u8]>;
    fn to_jwk(&self) -> Jwk;
    fn to_did(&self) -> Did {
        let bytes = self.bytes();
        let code = self.codec().code();

        let mut inner = Vec::with_capacity(code.len() + bytes.len());
        inner.extend(code);
        inner.extend(bytes);

        let id = multibase::encode(Base::Base58Btc, inner);

        Did {
            method_name: MethodName(NAME.to_string()),
            method_id: MethodId(id),
        }
    }
}

pub trait Multicodec {
    fn code_u64(&self) -> u64;
    fn code(&self) -> Vec<u8> {
        let mut buffer = unsigned_varint::encode::u64_buffer();
        unsigned_varint::encode::u64(self.code_u64(), &mut buffer).to_vec()
    }
}

pub trait WithMulticodec {
    fn codec(&self) -> Box<dyn Multicodec>;
}

pub trait KeyParser: WithMulticodec {
    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey>;
}
