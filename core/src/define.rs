use rand::{ Rng, CryptoRng };
use serde::{ Serialize, Deserialize };
use crate::common::Packing;
use crate::Error;


pub trait KeyExchange {
    type PrivateKey;
    type PublicKey: Packing;
    type Message: Packing + Serialize + for<'a> Deserialize<'a>;

    const SHARED_LENGTH: usize;

    fn exchange_to<R: Rng + CryptoRng>(r: &mut R, sharedkey: &mut [u8], pk: &Self::PublicKey)
        -> Result<Self::Message, Error>;
    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, m: &Self::Message) -> Result<(), Error>;
}


pub trait AeadCipher {
    const KEY_LENGTH: usize;
    const NONCE_LENGTH: usize;
    const TAG_LENGTH: usize;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error>;
    fn open(key: &[u8], nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), Error>;
}
