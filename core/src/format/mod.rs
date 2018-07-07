mod alg;
mod proto;

use std::fmt;
use serde::{ Serialize, Serializer, Deserialize, Deserializer };
use serde::de::{ self, Visitor, Unexpected };


pub type Message<'a> = Envelope<(SendMeta<'a>, Protocol, &'a [u8])>;

pub struct ENE;

#[derive(Serialize, Deserialize)]
pub struct Version(pub u16);

#[derive(Serialize, Deserialize)]
pub struct Envelope<T>(pub ENE, pub Version, pub T);

#[derive(Serialize, Deserialize)]
pub struct ID(pub String);

#[derive(Serialize, Deserialize)]
pub struct SendMeta<'a>(pub &'a str, pub Option<&'a str>);

#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Protocol {
    Sonly(alg::Signature),
    Ooake(alg::KeyExchange, alg::Encrypt),
    Sigae(bool, alg::Signature, alg::KeyExchange, alg::Encrypt)
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

        deserializer.deserialize_bytes(EneVisitor)
    }
}

impl Default for Version {
    fn default() -> Version {
        let v = semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
        Version(v.major as _)
    }
}
