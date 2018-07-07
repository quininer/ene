use std::fmt;
use serde::{ Deserialize, Deserializer };
use serde::de::{ self, Visitor };
use ed25519_dalek::{
    Keypair,
    PublicKey as PublicKey2, Signature as Signature2,
};
use crate::common::Packing;
use crate::Error;

#[derive(Serialize, Deserialize)]
pub struct SecretKey(pub(crate) Keypair);

#[derive(Serialize)]
pub struct PublicKey(pub(crate) PublicKey2);

#[derive(Serialize)]
pub struct Signature(pub(crate) Signature2);


impl Packing for Signature {
    const BYTES_LENGTH: usize = 64;

    fn read_bytes<F, R>(&self, f: F) -> R
        where F: FnOnce(&[u8]) -> R
    {
        f(&self.0.to_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == Self::BYTES_LENGTH {
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
                formatter.write_str("An ed25519 public key as a 32-byte compressed non-zero point, as specified in RFC8032")
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
                formatter.write_str("An ed25519 signature as 64 bytes, as specified in RFC8032.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Signature, E> where E: de::Error {
                match Signature::from_bytes(bytes) {
                    Ok(t) => Ok(t),
                    Err(Error::InvalidLength) => Err(de::Error::invalid_length(bytes.len(), &self)),
                    Err(Error::InvalidValue(msg)) => Err(de::Error::invalid_value(de::Unexpected::Other(msg), &self)),
                    Err(err) => Err(de::Error::custom(err))
                }
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}
