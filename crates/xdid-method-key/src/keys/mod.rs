use jose_jwk::Jwk;

#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "p384")]
pub mod p384;
#[cfg(feature = "p521")]
pub mod p521;

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

pub trait PublicKey: WithMulticodec {
    fn public_key(&self) -> &[u8];
    fn to_jwk(&self) -> Jwk;
}

pub trait KeyParser: WithMulticodec {
    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey>;
}
