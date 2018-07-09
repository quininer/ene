use rand::{ Rng, CryptoRng };
use serde::{ Serialize, Deserialize };
use crate::error;


pub trait Packing: Sized {
    const BYTES_LENGTH: usize;

    fn read_bytes<F, R>(&self, f: F) -> R
        where F: FnOnce(&[u8]) -> R;

    fn from_bytes(bytes: &[u8]) -> error::Result<Self>;
}

pub trait Signature {
    type PrivateKey;
    type PublicKey;
    type Signature: Packing + Serialize + for<'a> Deserialize<'a>;

    const NAME: &'static str;

    fn sign(sk: &Self::PrivateKey, message: &[u8]) -> Self::Signature;
    fn verify(pk: &Self::PublicKey, sig: &Self::Signature, message: &[u8]) -> bool;
}

pub trait KeyExchange {
    type PrivateKey;
    type PublicKey: Packing;
    type Message: Packing + Serialize + for<'a> Deserialize<'a>;

    const NAME: &'static str;
    const SHARED_LENGTH: usize;

    fn exchange_to<R: Rng + CryptoRng>(r: &mut R, sharedkey: &mut [u8], pk: &Self::PublicKey)
        -> error::Result<Self::Message>;
    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, m: &Self::Message) -> error::Result<()>;
}


pub trait AeadCipher {
    const NAME: &'static str;
    const KEY_LENGTH: usize;
    const NONCE_LENGTH: usize;
    const TAG_LENGTH: usize;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> error::Result<()>;
    fn open(key: &[u8], nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> error::Result<()>;
}
