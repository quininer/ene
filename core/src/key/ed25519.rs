use ed25519_dalek::{
    Keypair,
    PublicKey as PublicKey2, Signature as Signature2,
};
use crate::Error;

pub struct SecretKey(pub(crate) Keypair);
pub struct PublicKey(pub(crate) PublicKey2);
pub struct Signature(pub(crate) Signature2);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, Error> {
        if bytes.len() == 64 {
            check!(&bytes[..32]);
            check!(&bytes[32..]);
            Ok(Signature(Signature2::from_bytes(bytes)?))
        } else {
            Err(Error::InvalidLength)
        }
    }
}
