#![feature(non_exhaustive, underscore_imports, const_fn)]

#[macro_use] extern crate failure;
#[macro_use] extern crate arrayref;
#[macro_use] extern crate serde_derive;
extern crate rand;
extern crate subtle;
extern crate sha3;
extern crate digest;
extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate generic_array;
extern crate aes;
extern crate colm;
extern crate serde;
extern crate semver;
extern crate siphasher;

#[macro_use] pub mod common;
pub mod define;
pub mod proto;
pub mod key;
pub mod aead;
pub mod format;
pub mod error;

use std::collections::BTreeMap;
use rand::{ Rng, CryptoRng, OsRng };
use crate::proto::Protocol;
use crate::format::Message;
use crate::define::ToVec;


pub struct Ene {
    id: String,
    key: key::SecretKey
}

pub struct GenerateBuilder {
    pub ed25519: bool,
    pub ristretto_dh: bool
}

pub struct And<'a> {
    ene: &'a Ene,
    target: (&'a str, &'a key::PublicKey)
}

impl Default for GenerateBuilder {
    fn default() -> Self {
        GenerateBuilder {
            ed25519: true,
            ristretto_dh: true
        }
    }
}

impl GenerateBuilder {
    pub fn generate<RNG: Rng + CryptoRng>(&self, id: &str, rng: &mut RNG) -> Ene {
        use crate::key::{ ed25519, ristretto_dh };

        let ed25519_sk =
            if self.ed25519 { Some(ed25519::SecretKey::generate(rng)) }
            else { None };
        let ristretto_dh_sk =
            if self.ristretto_dh { Some(ristretto_dh::SecretKey::generate(rng)) }
            else { None };

        Ene {
            id: id.to_owned(),
            key: key::SecretKey{
                ed25519: ed25519_sk,
                ristretto_dh: ristretto_dh_sk
            }
        }
    }
}
