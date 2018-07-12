use std::fmt;
use serde::{ Serialize, Serializer, Deserialize, Deserializer };
use serde::de::{ self, Visitor, Unexpected };
use serde_bytes::{ ByteBuf, Bytes };
use crate::key;
use crate::define::Packing;
use crate::proto::{ alg, Protocol };


pub type PrivateKey = Envelope<(ID, alg::Encrypt, ByteBuf, ByteBuf)>;

pub type PublicKey = Envelope<(ID, key::PublicKey)>;

pub type Message = Envelope<(Meta, Protocol, ByteBuf)>;

pub type MessageBorrowed<'a> = Envelope<(Meta, Protocol, Bytes<'a>)>;

pub struct ENE;

#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(Serialize, Deserialize)]
pub struct Version(pub u16);

#[derive(Serialize, Deserialize)]
pub struct Envelope<T>(pub ENE, pub Version, pub T);

pub type ID = String;

#[derive(Serialize, Deserialize)]
pub struct Meta {
    /// Sender ID and PublicKey
    pub s: (ID, key::PublicKey),

    /// Receiver ID and Short PublicKey
    pub r: Option<(ID, key::ShortPublicKey)>
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[derive(Serialize, Deserialize)]
pub struct Short(pub u128);

impl Default for Version {
    fn default() -> Version {
        let v = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        Version(v.major as _)
    }
}

impl Serialize for ENE {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str("ENE")
    }
}

impl<'de> Deserialize<'de> for ENE {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct EneVisitor;

        impl<'d> Visitor<'d> for EneVisitor {
            type Value = ENE;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ENE str")
            }

            fn visit_str<E>(self, v: &str) -> Result<ENE, E> where E: de::Error {
                if v == "ENE" {
                    Ok(ENE)
                } else {
                    Err(de::Error::invalid_type(Unexpected::Str(v), &self))
                }
            }
        }

        deserializer.deserialize_str(EneVisitor)
    }
}

impl<'a, T: Packing> From<&'a T> for Short {
    fn from(t: &'a T) -> Short {
        use std::hash::Hasher;
        use siphasher::sip128::{ Hasher128, SipHasher };

        let mut hasher = SipHasher::new();
        t.read_bytes(|bytes| hasher.write(bytes));
        let hash = hasher.finish128();
        Short(u128::from_bytes(hash.as_bytes()))
    }
}

impl fmt::Debug for Short {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#032x}", self.0)
    }
}
