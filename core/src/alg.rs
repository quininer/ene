//! Algorithm

use std::str::FromStr;
use crate::key;
use crate::error::ParseError;
use crate::define::AeadCipher;
use crate::aead::aes128colm0::Aes128Colm0;

#[cfg(feature = "post-quantum")]
use crate::aead::norx_mrs::NorxMRS;


#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[derive(Clone, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Protocol {
    Sonly(Signature),
    Ooake(KeyExchange, Encrypt),
    Sigae(bool, Signature, KeyExchange, Encrypt)
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Signature {
    Ed25519
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyExchange {
    RistrettoDH,
    #[cfg(feature = "post-quantum")] Kyber
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Encrypt {
    Aes128Colm0,
    #[cfg(feature = "post-quantum")] NorxMRS
}

impl Protocol {
    pub const fn default_name() -> &'static str {
        "ooake-ristrettodh-aes128colm0"
    }
}

impl Signature {
    pub const fn names() -> &'static [&'static str] {
        &["ed25519"]
    }
}

impl KeyExchange {
    pub const fn names() -> &'static [&'static str] {
        &[
            "ristrettodh",
            #[cfg(feature = "post-quantum")] "kyber"
        ]
    }
}

impl Encrypt {
    pub const fn names() -> &'static [&'static str] {
        &[
            "aes128colm0",
            #[cfg(feature = "post-quantum")] "norxmrs"
        ]
    }

    pub fn take(&self) -> &'static dyn AeadCipher {
        match self {
            Encrypt::Aes128Colm0 => &Aes128Colm0,
            #[cfg(feature = "post-quantum")] Encrypt::NorxMRS => &NorxMRS
        }
    }
}

impl FromStr for Protocol {
    type Err = ParseError;

    #[allow(unreachable_patterns)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.split('-');

        let proto = s.next()?.trim().to_lowercase();

        let proto = match proto.as_str() {
            "sonly" => Protocol::Sonly(Signature::from_str(s.next()?)?),
            "ooake" => {
                let kx = KeyExchange::from_str(s.next()?)?;
                match kx {
                    KeyExchange::RistrettoDH => Protocol::Ooake(kx, Encrypt::from_str(s.next()?)?),
                    _ => return Err(ParseError::NotAvailable(proto.into())) // ooake only support RistrettoDH
                }
            },
            alg @ "sigae" | alg @ "sigae+" => Protocol::Sigae(
                alg.ends_with('+'),
                Signature::from_str(s.next()?)?,
                KeyExchange::from_str(s.next()?)?,
                Encrypt::from_str(s.next()?)?
            ),
            _ => return Err(ParseError::Unknown(proto.into()))
        };

        Ok(proto)
    }
}

impl FromStr for Signature {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "ed25519" => Ok(Signature::Ed25519),
            _ => Err(ParseError::Unknown(s.into()))
        }
    }
}

impl FromStr for KeyExchange {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        match s.as_str() {
            "ristrettodh" => Ok(KeyExchange::RistrettoDH),
            #[cfg(feature = "post-quantum")] "kyber" => Ok(KeyExchange::Kyber),
            _ => Err(ParseError::Unknown(s.into()))
        }
    }
}

impl FromStr for Encrypt {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        match s.as_str() {
            "aes128colm0" => Ok(Encrypt::Aes128Colm0),
            #[cfg(feature = "post-quantum")] "norxmrs" => Ok(Encrypt::NorxMRS),
            _ => Err(ParseError::Unknown(s.into()))
        }
    }
}

impl Protocol {
    #[allow(unreachable_patterns)]
    pub fn loss(&self, send: &key::SecretKey, recv: &key::PublicKey)
        -> Result<(key::PublicKey, Option<key::ShortPublicKey>), ParseError>
    {
        use crate::define::{ Signature as _, KeyExchange as _ };
        use crate::format::Short;
        use crate::key::{
            ed25519::{ self, Ed25519 },
            ristrettodh::{ self, RistrettoDH }
        };
        #[cfg(feature = "post-quantum")]
        use crate::key::kyber::{ self, Kyber };

        macro_rules! try_unwrap {
            ( $k:expr ; $alg:expr ) => {
                match $k {
                    Some(k) => k,
                    None => return Err(crate::error::ParseError::NotAvailable($alg.into()))
                }
            }
        }

        match self {
            Protocol::Sonly(Signature::Ed25519) => {
                let sig_sk = try_unwrap!(&send.ed25519; Ed25519::NAME);
                let sig_pk = ed25519::PublicKey::from_secret(sig_sk);

                let smap = key::PublicKey {
                    ed25519: Some(sig_pk),
                    ..Default::default()
                };

                Ok((smap, None))
            },
            Protocol::Ooake(KeyExchange::RistrettoDH, _) => {
                let ska = try_unwrap!(&send.ristrettodh; RistrettoDH::NAME);
                let pka = ristrettodh::PublicKey::from_secret(ska);
                let pkb = try_unwrap!(&recv.ristrettodh; RistrettoDH::NAME);

                let smap = key::PublicKey {
                    ristrettodh: Some(pka),
                    ..Default::default()
                };
                let rmap = key::ShortPublicKey {
                    ristrettodh: Some(Short::from(pkb)),
                    ..Default::default()
                };

                Ok((smap, Some(rmap)))
            },
            Protocol::Ooake(..) => {
                Err(ParseError::NotAvailable("RistrettoDH Only".into()))
            },
            Protocol::Sigae(_, sig, kex, _) => {
                let mut smap = key::PublicKey::default();
                let mut rmap = key::ShortPublicKey::default();

                match sig {
                    Signature::Ed25519 => {
                        let sk = try_unwrap!(&send.ed25519; Ed25519::NAME);
                        let pk = ed25519::PublicKey::from_secret(sk);

                        smap.ed25519 = Some(pk);
                    }
                }

                match kex {
                    KeyExchange::RistrettoDH => {
                        let ska = try_unwrap!(&send.ristrettodh; RistrettoDH::NAME);
                        let pka = ristrettodh::PublicKey::from_secret(ska);
                        let pkb = try_unwrap!(&recv.ristrettodh; RistrettoDH::NAME);

                        smap.ristrettodh = Some(pka);
                        rmap.ristrettodh = Some(Short::from(pkb));
                    },
                    #[cfg(feature = "post-quantum")]
                    KeyExchange::Kyber => {
                        let ska = try_unwrap!(&send.kyber; Kyber::NAME);
                        let pka = kyber::PublicKey::from_secret(ska);
                        let pkb = try_unwrap!(&recv.kyber; Kyber::NAME);

                        smap.kyber = Some(pka);
                        rmap.kyber = Some(Short::from(pkb));
                    }
                }

                Ok((smap, Some(rmap)))
            }
        }
    }
}
