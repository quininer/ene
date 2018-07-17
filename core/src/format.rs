use std::fmt;
use std::marker::PhantomData;
use serde::{ Serialize, Serializer, Deserialize, Deserializer };
use serde::de::{ self, Visitor, Unexpected };
use serde_bytes::ByteBuf;
use crate::{ alg, key };
use crate::define::{ Packing, Type };
use crate::proto::{ Protocol };


pub type PrivateKey = Envelope<SK, (String, alg::Encrypt, ByteBuf, ByteBuf)>;

pub type PublicKey = Envelope<PK, (String, key::PublicKey)>;

pub type Message = Envelope<MSG, (Meta, Protocol, ByteBuf)>;

pub struct ENE<T: Type>(PhantomData<T>);

#[derive(Serialize, Deserialize)] pub struct PK;
#[derive(Serialize, Deserialize)] pub struct SK;
#[derive(Serialize, Deserialize)] pub struct MSG;

impl Type for PK {
    const NAME: &'static str = "PK";
}

impl Type for SK {
    const NAME: &'static str = "SK";
}

impl Type for MSG {
    const NAME: &'static str = "MSG";
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(Serialize, Deserialize)]
pub struct Version(pub u16);

#[derive(Serialize, Deserialize)]
pub struct Envelope<T: Type, V>(pub ENE<T>, pub Version, pub V);

#[derive(Serialize, Deserialize)]
pub struct Meta {
    /// Sender String and PublicKey
    pub s: (String, key::PublicKey),

    /// Receiver String and Short PublicKey
    pub r: Option<(String, key::ShortPublicKey)>
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[derive(Serialize, Deserialize)]
pub struct Short(pub u128);

impl<T: Type, V> From<V> for Envelope<T, V> {
    fn from(value: V) -> Envelope<T, V> {
        Envelope(ENE(PhantomData), Version::default(), value)
    }
}

impl<T: Type, V> Envelope<T, V> {
    pub fn unwrap(self) -> V {
        let Envelope(_, version, value) = self;
        assert_eq!(version, Version::default());
        value
    }
}

impl Default for Version {
    fn default() -> Version {
        let v = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        Version(v.major as _)
    }
}

impl<T: Type> Serialize for ENE<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.collect_str(&format_args!("ENE{}", T::NAME))
    }
}

impl<'de, T: Type> Deserialize<'de> for ENE<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct EneVisitor<T>(PhantomData<T>);

        impl<'d, T: Type> Visitor<'d> for EneVisitor<T> {
            type Value = ENE<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ENE str")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where E: de::Error
            {
                if v.starts_with("ENE") && &v[3..] == T::NAME {
                    Ok(ENE(PhantomData))
                } else {
                    Err(de::Error::invalid_type(Unexpected::Str(v), &self))
                }
            }
        }

        deserializer.deserialize_str(EneVisitor(PhantomData))
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
