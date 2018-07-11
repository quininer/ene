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
use crate::format::Message;
use crate::proto::{ alg, Protocol, ooake, sigae, sonly };
use crate::key::ed25519::{ self, Ed25519 };
use crate::key::ristretto_dh::{ self, RistrettoDH };
use crate::aead::aes128colm0::Aes128Colm0;
use crate::define::{ Signature, KeyExchange, AeadCipher, Serde };


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
            id: id.to_string(),
            key: key::SecretKey{
                ed25519: ed25519_sk,
                ristretto_dh: ristretto_dh_sk
            }
        }
    }
}

impl Ene {
    pub fn and<'a>(&'a self, id: &'a str, target: &'a key::PublicKey) -> And<'a> {
        And {
            ene: self,
            target: (id, target)
        }
    }

    pub fn to_public(&self) -> key::PublicKey {
        use crate::key::{ ed25519, ristretto_dh };

        key::PublicKey {
            ed25519: self.key.ed25519.as_ref().map(ed25519::PublicKey::from_secret),
            ristretto_dh: self.key.ristretto_dh.as_ref().map(ristretto_dh::PublicKey::from_secret)
        }
    }
}

impl<'a> And<'a> {
    pub fn sendto<SER: Serde>(&self, proto: &Protocol, aad: &[u8], message: &[u8]) -> error::Result<Message> {
        use crate::format::{ Meta, Short, Envelope, ENE, Version };

        let v = Version::default();

        let And {
            ene: Ene { id: ida, key: ska },
            target: (idb, pkb)
        } = self;

        let mut rng = OsRng::new()?;

        match *proto {
            Protocol::Sonly(alg::Signature::Ed25519) => {
                let mut smap = BTreeMap::new();

                let sig_name = Ed25519::NAME;
                let sig_sk = try_unwrap!(&ska.ed25519; sig_name);
                let sig_pk = ed25519::PublicKey::from_secret(sig_sk);
                smap.insert(sig_name.into(), SER::to_vec(&sig_pk)?);

                let msg = sonly::send::<Ed25519>(sig_sk, &aad);
                let msg = SER::to_vec(&msg)?;

                let meta = Meta {
                    s: (ida.to_string(), smap),
                    r: None
                };

                Ok(Envelope(ENE, v, (meta, proto.clone(), msg)))
            },
            Protocol::Ooake(alg::KeyExchange::RistrettoDH, enc) => {
                let mut smap = BTreeMap::new();
                let mut rmap = BTreeMap::new();

                let aead = match enc {
                    alg::Encrypt::Aes128Colm0 => &Aes128Colm0 as &'static AeadCipher
                };

                let dh_name = RistrettoDH::NAME;
                let ska = try_unwrap!(&ska.ristretto_dh; dh_name);
                let pka = ristretto_dh::PublicKey::from_secret(ska);
                let pkb = try_unwrap!(&pkb.ristretto_dh; dh_name);
                smap.insert(dh_name.into(), SER::to_vec(&pka)?);
                rmap.insert(dh_name.into(), Short::from(pkb));

                let msg = ooake::send(
                    &mut rng,
                    aead,
                    (ida, ska),
                    (idb, pkb),
                    aad,
                    message
                )?;
                let msg = SER::to_vec(&msg)?;

                let meta = Meta {
                    s: (ida.to_string(), smap),
                    r: Some((idb.to_string(), rmap))
                };

                Ok(Envelope(ENE, v, (meta, proto.clone(), msg)))
            },
            Protocol::Sigae(flag, alg::Signature::Ed25519, alg::KeyExchange::RistrettoDH, enc) => {
                let mut smap = BTreeMap::new();
                let mut rmap = BTreeMap::new();

                let aead = match enc {
                    alg::Encrypt::Aes128Colm0 => &Aes128Colm0 as &'static AeadCipher
                };

                let sig_name = Ed25519::NAME;
                let dh_name = RistrettoDH::NAME;
                let sigsk_a = try_unwrap!(&ska.ed25519; sig_name);
                let sigpk_a = ed25519::PublicKey::from_secret(sigsk_a);
                let dhpk_b = try_unwrap!(&pkb.ristretto_dh; dh_name);
                smap.insert(sig_name.into(), SER::to_vec(&sigpk_a)?);
                rmap.insert(dh_name.into(), Short::from(dhpk_b));

                let msg = sigae::send::<_, Ed25519, RistrettoDH>(
                    &mut rng,
                    aead,
                    (ida, sigsk_a),
                    (idb, dhpk_b),
                    aad,
                    message,
                    flag
                )?;
                let msg = SER::to_vec(&msg)?;

                let meta = Meta {
                    s: (ida.to_string(), smap),
                    r: Some((idb.to_string(), rmap))
                };

                Ok(Envelope(ENE, v, (meta, proto.clone(), msg)))
            }
        }
    }

    pub fn recvfrom<DE: Serde>(&self, proto: &Protocol, aad: &[u8], message: &[u8]) -> error::Result<Vec<u8>> {
        let And {
            ene: Ene { id: idb, key: skb },
            target: (ida, pka)
        } = self;

        match *proto {
            Protocol::Sonly(alg::Signature::Ed25519) => {
                let msg: sonly::Message<Ed25519> = DE::from_slice(message)?;

                let sig_pk = try_unwrap!(&pka.ed25519; Ed25519::NAME);
                sonly::recv::<Ed25519>(sig_pk, &msg, aad)?;

                Ok(Vec::new())
            },
            Protocol::Ooake(alg::KeyExchange::RistrettoDH, enc) => {
                let aead = match enc {
                    alg::Encrypt::Aes128Colm0 => &Aes128Colm0 as &'static AeadCipher
                };

                let (msg, c): (ooake::Message, Vec<u8>) = DE::from_slice(message)?;

                let dhsk_b = try_unwrap!(&skb.ristretto_dh; RistrettoDH::NAME);
                let dhpk_a = try_unwrap!(&pka.ristretto_dh; RistrettoDH::NAME);
                ooake::recv(
                    aead,
                    (idb, dhsk_b),
                    (ida, dhpk_a),
                    &msg,
                    aad,
                    &c
                )
            },
            Protocol::Sigae(flag, alg::Signature::Ed25519, alg::KeyExchange::RistrettoDH, enc) => {
                let aead = match enc {
                    alg::Encrypt::Aes128Colm0 => &Aes128Colm0 as &'static AeadCipher
                };

                let (msg, c): (sigae::Message<RistrettoDH>, Vec<u8>) = DE::from_slice(message)?;

                let dhsk_b = try_unwrap!(&skb.ristretto_dh; RistrettoDH::NAME);
                let dhpk_b = ristretto_dh::PublicKey::from_secret(dhsk_b);
                let sigpk_a = try_unwrap!(&pka.ed25519; Ed25519::NAME);
                sigae::recv::<Ed25519, RistrettoDH>(
                    aead,
                    (idb, dhsk_b, &dhpk_b),
                    (ida, sigpk_a),
                    &msg,
                    aad,
                    &c,
                    flag
                )
            }
        }
    }
}
