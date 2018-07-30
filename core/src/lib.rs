#![feature(nll, non_exhaustive, underscore_imports, try_from, try_trait, const_fn, raw_identifiers)]

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
extern crate serde_bytes;
extern crate semver;
extern crate siphasher;

#[cfg(feature = "post-quantum")]
extern crate sarkara;

#[macro_use] mod common;
pub mod define;
pub mod proto;
pub mod alg;
pub mod key;
pub mod aead;
pub mod format;
pub mod error;

use std::str::FromStr;
use rand::{ Rng, CryptoRng, OsRng };
use serde_bytes::{ ByteBuf, Bytes };
use crate::alg::Protocol;
use crate::format::Message;
use crate::error::ParseError;
use crate::proto::{ ooake, sigae, sonly };
use crate::key::ed25519::{ self, Ed25519 };
use crate::key::ristrettodh::{ self, RistrettoDH };
use crate::define::{ Signature, KeyExchange, Serde };

#[cfg(feature = "post-quantum")] use crate::key::kyber::{ self, Kyber };


pub struct Ene {
    id: String,
    key: key::SecretKey
}

/// ENE PrivateKey Builder
pub struct Builder {
    pub ed25519: bool,
    pub ristrettodh: bool,
    #[cfg(feature = "post-quantum")] pub kyber: bool
}

pub struct And<'a> {
    ene: &'a Ene,
    target: (&'a str, &'a key::PublicKey)
}

impl Default for Builder {
    fn default() -> Self {
        Builder {
            ed25519: true, ristrettodh: true,
            #[cfg(feature = "post-quantum")] kyber: false
        }
    }
}

impl Builder {
    pub fn empty() -> Self {
        Builder {
            ed25519: false, ristrettodh: false,
            #[cfg(feature = "post-quantum")] kyber: false
        }
    }

    pub fn all() -> Self {
        Builder {
            ed25519: true, ristrettodh: true,
            #[cfg(feature = "post-quantum")] kyber: true
        }

    }

    pub fn generate<RNG: Rng + CryptoRng>(&self, id: &str, rng: &mut RNG) -> Ene {
        let ed25519_sk =
            if self.ed25519 { Some(ed25519::SecretKey::generate(rng)) }
            else { None };
        let ristrettodh_sk =
            if self.ristrettodh { Some(ristrettodh::SecretKey::generate(rng)) }
            else { None };

        #[cfg(feature = "post-quantum")]
        let kyber_sk =
            if self.kyber { Some(kyber::SecretKey::generate(rng)) }
            else { None };

        Ene {
            id: id.to_string(),
            key: key::SecretKey {
                ed25519: ed25519_sk,
                ristrettodh: ristrettodh_sk,
                #[cfg(feature = "post-quantum")] kyber: kyber_sk
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

    pub fn from(id: &str, key: key::SecretKey) -> Self {
        Ene { id: id.to_string(), key }
    }

    pub fn get_id(&self) -> &str {
        self.id.as_ref()
    }

    pub fn as_secret(&self) -> &key::SecretKey {
        &self.key
    }

    pub fn into_secret(self) -> key::SecretKey {
        self.key
    }
}

impl<'a> And<'a> {
    pub fn sendto<SER: Serde>(&self, proto: &Protocol, aad: &[u8], message: &[u8])
        -> Result<Message, error::Error<SER::Error>>
    {
        use crate::format::{ Meta, Envelope };

        let And {
            ene: Ene { id: ida, key: ska },
            target: (idb, pkb)
        } = self;

        let mut rng = OsRng::new()?;

        let (smap, rmap) = proto.loss(ska, pkb)?;
        let meta = Meta {
            s: (ida.to_string(), smap),
            r: rmap.map(|rmap| (idb.to_string(), rmap))
        };

        let msg = match *proto {
            Protocol::Sonly(alg::Signature::Ed25519) => {
                let sig_sk = try_unwrap!(&ska.ed25519; Ed25519::NAME);
                let msg = sonly::send::<Ed25519>((ida, sig_sk), aad, message);
                ByteBuf::from(SER::to_vec(&msg)?)
            },
            Protocol::Ooake(alg::KeyExchange::RistrettoDH, enc) => {
                let aead = enc.take();

                let ska = try_unwrap!(&ska.ristrettodh; RistrettoDH::NAME);
                let pkb = try_unwrap!(&pkb.ristrettodh; RistrettoDH::NAME);

                let (msg, c) = ooake::send(
                    &mut rng,
                    aead,
                    (ida, ska),
                    (idb, pkb),
                    aad,
                    message
                )?;
                let msg = (msg, ByteBuf::from(c));
                ByteBuf::from(SER::to_vec(&msg)?)
            },
            #[cfg(feature = "post-quantum")] Protocol::Ooake(alg::KeyExchange::Kyber, _)
                => return Err(ParseError::NotAvailable("RistrettoDH Only".into()).into()),
            Protocol::Sigae(flag, alg::Signature::Ed25519, alg::KeyExchange::RistrettoDH, enc) => {
                let aead = enc.take();

                let sigsk_a = try_unwrap!(&ska.ed25519; Ed25519::NAME);
                let dhpk_b = try_unwrap!(&pkb.ristrettodh; RistrettoDH::NAME);

                let (msg, c) = sigae::send::<_, Ed25519, RistrettoDH>(
                    &mut rng,
                    aead,
                    (ida, sigsk_a),
                    (idb, dhpk_b),
                    aad,
                    message,
                    flag
                )?;
                let msg = (msg, ByteBuf::from(c));
                ByteBuf::from(SER::to_vec(&msg)?)
            },
            #[cfg(feature = "post-quantum")]
            Protocol::Sigae(flag, alg::Signature::Ed25519, alg::KeyExchange::Kyber, enc) => {
                let aead = enc.take();

                let sigsk_a = try_unwrap!(&ska.ed25519; Ed25519::NAME);
                let dhpk_b = try_unwrap!(&pkb.kyber; Kyber::NAME);

                let (msg, c) = sigae::send::<_, Ed25519, Kyber>(
                    &mut rng,
                    aead,
                    (ida, sigsk_a),
                    (idb, dhpk_b),
                    aad,
                    message,
                    flag
                )?;
                let msg = (msg, ByteBuf::from(c));
                ByteBuf::from(SER::to_vec(&msg)?)
            }
        };

        Ok(Envelope::from((meta, proto.clone(), msg)))
    }

    pub fn recvfrom<DE: Serde>(&self, proto: &Protocol, aad: &[u8], message: &[u8])
        -> Result<Vec<u8>, error::Error<DE::Error>>
    {
        let And {
            ene: Ene { id: idb, key: skb },
            target: (ida, pka)
        } = self;

        match *proto {
            Protocol::Sonly(alg::Signature::Ed25519) => {
                let msg: sonly::Message<Ed25519> = DE::from_slice(message)?;

                let sig_pk = try_unwrap!(&pka.ed25519; Ed25519::NAME);
                sonly::recv::<Ed25519>((ida, sig_pk), &msg, aad, message)?;

                Ok(Vec::new())
            },
            Protocol::Ooake(alg::KeyExchange::RistrettoDH, enc) => {
                let aead = enc.take();

                let (msg, c): (ooake::Message, Bytes) = DE::from_slice(message)?;

                let dhsk_b = try_unwrap!(&skb.ristrettodh; RistrettoDH::NAME);
                let dhpk_a = try_unwrap!(&pka.ristrettodh; RistrettoDH::NAME);
                ooake::recv(
                    aead,
                    (idb, dhsk_b),
                    (ida, dhpk_a),
                    &msg,
                    aad,
                    &c
                )
                    .map_err(Into::into)
            },
            #[cfg(feature = "post-quantum")] Protocol::Ooake(alg::KeyExchange::Kyber, _)
                => return Err(ParseError::NotAvailable("Kyber".into()).into()),
            Protocol::Sigae(flag, alg::Signature::Ed25519, alg::KeyExchange::RistrettoDH, enc) => {
                let aead = enc.take();

                let (msg, c): (sigae::Message<RistrettoDH>, Bytes) = DE::from_slice(message)?;

                let dhsk_b = try_unwrap!(&skb.ristrettodh; RistrettoDH::NAME);
                let dhpk_b = ristrettodh::PublicKey::from_secret(dhsk_b);
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
                    .map_err(Into::into)
            },
            #[cfg(feature = "post-quantum")]
            Protocol::Sigae(flag, alg::Signature::Ed25519, alg::KeyExchange::Kyber, enc) => {
                let aead = enc.take();

                let (msg, c): (sigae::Message<Kyber>, Bytes) = DE::from_slice(message)?;

                let dhsk_b = try_unwrap!(&skb.kyber; Kyber::NAME);
                let dhpk_b = kyber::PublicKey::from_secret(dhsk_b);
                let sigpk_a = try_unwrap!(&pka.ed25519; Ed25519::NAME);
                sigae::recv::<Ed25519, Kyber>(
                    aead,
                    (idb, dhsk_b, &dhpk_b),
                    (ida, sigpk_a),
                    &msg,
                    aad,
                    &c,
                    flag
                )
                    .map_err(Into::into)
            }
        }
    }
}

impl FromStr for Builder {
    type Err = ParseError;

    fn from_str(algorithms: &str) -> Result<Self, Self::Err> {
        let mut builder = Builder::empty();

        for a in algorithms.split(',') {
            match a.trim().to_lowercase().as_str() {
                "ed25519" => builder.ed25519 = true,
                "ristrettodh" => builder.ristrettodh = true,
                #[cfg(feature = "post-quantum")] "kyber" => builder.kyber = true,
                a => return Err(ParseError::Unknown(a.to_string().into()))
            }
        }

        Ok(builder)
    }
}
