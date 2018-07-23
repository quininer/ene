//! Trait define

use rand::{ Rng, CryptoRng };
use serde::{ Serialize, Deserialize };
use crate::error::{ self, ProtoError };


pub trait Packing: Sized {
    const BYTES_LENGTH: usize;

    fn read_bytes<F, R>(&self, f: F) -> R
        where F: FnOnce(&[u8]) -> R;

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError>;
}

pub trait Signature {
    type PrivateKey;
    type PublicKey;
    type Signature: Packing;

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
        -> Result<Self::Message, ProtoError>;
    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, m: &Self::Message) -> Result<(), ProtoError>;
}

pub trait AeadCipher {
    fn key_length(&self) -> usize;
    fn nonce_length(&self) -> usize;
    fn tag_length(&self) -> usize;

    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), ProtoError>;
    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), ProtoError>;
}

pub trait Serde {
    type Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, error::Error<Self::Error>>;

    fn from_slice<'a, T: Deserialize<'a>>(slice: &'a [u8]) -> Result<T, error::Error<Self::Error>>;
}

pub trait Type {
    const NAME: &'static str;
}
