#![feature(non_exhaustive, underscore_imports)]

#[macro_use] extern crate failure;
#[macro_use] extern crate arrayref;
extern crate rand;
extern crate subtle;
extern crate serde;

extern crate sha3;
extern crate digest;

extern crate curve25519_dalek;
extern crate ed25519_dalek;

extern crate generic_array;
extern crate aes;
extern crate colm;


#[macro_use] pub mod common;
pub mod define;
pub mod proto;
pub mod key;
pub mod aead;


#[derive(Debug, Fail)]
#[non_exhaustive]
#[must_use]
pub enum Error {
    #[fail(display = "Compressed point decompress error")]
    Decompress,

    #[fail(display = "Not allow zero value")]
    Zero,

    #[fail(display = "Invalid length")]
    InvalidLength,

    #[fail(display = "Ed25519 Decoding Error: {}", _0)]
    Ed25519(ed25519_dalek::DecodingError),

    #[fail(display = "Fail to pass verification")]
    VerificationFailed,
}

impl From<ed25519_dalek::DecodingError> for Error {
    fn from(err: ed25519_dalek::DecodingError) -> Error {
        Error::Ed25519(err)
    }
}
