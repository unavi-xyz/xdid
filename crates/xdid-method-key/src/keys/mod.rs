use jose_jwk::Jwk;

#[cfg(feature = "ed25519")]
pub mod ed25519;

pub trait PublicKey {
    /// Multicodec identifier for the public key.
    fn public_code(&self) -> u64;
    fn public_key(&self) -> &[u8];
    fn to_jwk(&self) -> Jwk;
}

pub trait KeyParser {
    /// Multicodec identifier for the public key.
    fn code_u64(&self) -> u64;
    /// Multicodec identifier for the public key.
    fn code(&self) -> Vec<u8> {
        let mut buffer = unsigned_varint::encode::u64_buffer();
        unsigned_varint::encode::u64(self.code_u64(), &mut buffer).to_vec()
    }

    fn parse(&self, public_key: Vec<u8>) -> Box<dyn PublicKey>;
}
