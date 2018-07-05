use std::fmt;
use serde::{ Deserialize, Deserializer };
use serde::de::{ self, Visitor };
use ed25519_dalek::{
    Keypair,
    PublicKey as PublicKey2, Signature as Signature2,
};
use crate::Error;

#[derive(Serialize, Deserialize)]
pub struct SecretKey(pub(crate) Keypair);

#[derive(Serialize)]
pub struct PublicKey(pub(crate) PublicKey2);

#[derive(Serialize)]
pub struct Signature(pub(crate) Signature2);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, Error> {
        if bytes.len() == 64 {
            check!(&bytes[..32]);
            check!(&bytes[32..]);
            Ok(Signature(Signature2::from_bytes(bytes)?))
        } else {
            Err(Error::InvalidLength)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct PublicKeyVisitor;

        impl<'d> Visitor<'d> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("An ed25519 public key as a 32-byte compressed point, as specified in RFC8032")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<PublicKey, E> where E: de::Error {
                if let Ok(pk) = PublicKey2::from_bytes(bytes) {
                    check!(serde bytes);
                    Ok(PublicKey(pk))
                } else {
                    Err(de::Error::invalid_length(bytes.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct SignatureVisitor;

        impl<'d> Visitor<'d> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("An ed25519 public key as a 32-byte compressed point, as specified in RFC8032")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Signature, E> where E: de::Error {
                if bytes.len() == 64 {
                    Signature::from_bytes(bytes)
                        .map_err(de::Error::custom)
                } else {
                    Err(de::Error::invalid_length(bytes.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}
