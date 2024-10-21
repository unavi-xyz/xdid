#[cfg(feature = "ed25519")]
pub mod ed25519;

pub trait Key {
    /// Multicodec identifier for the public key.
    fn public_code(&self) -> u64;
    fn public_key(&self) -> &[u8];
}
