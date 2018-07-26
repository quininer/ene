use std::str::FromStr;
use crate::error::ParseError;
use crate::define::AeadCipher;
use crate::aead::aes128colm0::Aes128Colm0;


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
    RistrettoDH
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Encrypt {
    Aes128Colm0
}

impl Signature {
    pub const fn names() -> &'static [&'static str] {
        &["ed25519"]
    }
}

impl KeyExchange {
    pub const fn names() -> &'static [&'static str] {
        &["ristrettodh"]
    }
}

impl Encrypt {
    pub const fn names() -> &'static [&'static str] {
        &["aes128colm0"]
    }

    pub fn take(&self) -> &'static dyn AeadCipher {
        match self {
            Encrypt::Aes128Colm0 => &Aes128Colm0
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
            _ => Err(ParseError::Unknown(s.into()))
        }
    }
}
