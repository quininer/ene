//! Ed25519

use std::fmt;
use rand::{ Rng, CryptoRng };
use serde::{ Deserialize, Deserializer };
use serde::de::{ self, Visitor };
use sha3::Sha3_512;
use ed25519_dalek::{
    Keypair,
    PublicKey as PublicKey2, Signature as Signature2,
};
use crate::define::{ Packing, Signature as Signature3 };
use crate::format::Short;
use crate::error::ProtoError;


#[derive(Serialize, Deserialize)]
pub struct SecretKey(pub(crate) Keypair);

#[derive(Eq, PartialEq)]
#[derive(Serialize)]
pub struct PublicKey(pub(crate) PublicKey2);

#[derive(Serialize)]
pub struct Signature(pub(crate) Signature2);

impl SecretKey {
    pub fn generate<RNG: Rng + CryptoRng>(rng: &mut RNG) -> SecretKey {
        SecretKey(Keypair::generate::<Sha3_512, _>(rng))
    }
}

impl PublicKey {
    pub fn from_secret(SecretKey(sk): &SecretKey) -> PublicKey {
        PublicKey(sk.public)
    }
}

impl Packing for PublicKey {
    const BYTES_LENGTH: usize = 32;

    fn read_bytes<F, R>(&self, f: F) -> R
        where F: FnOnce(&[u8]) -> R
    {
        f(&self.0.to_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() == Self::BYTES_LENGTH {
            check!(bytes);
            Ok(PublicKey(PublicKey2::from_bytes(bytes)?))
        } else {
            Err(ProtoError::InvalidLength)
        }
    }
}

impl Packing for Signature {
    const BYTES_LENGTH: usize = 64;

    fn read_bytes<F, R>(&self, f: F) -> R
        where F: FnOnce(&[u8]) -> R
    {
        f(&self.0.to_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() == Self::BYTES_LENGTH {
            check!(&bytes[..32]);
            check!(&bytes[32..]);
            Ok(Signature(Signature2::from_bytes(bytes)?))
        } else {
            Err(ProtoError::InvalidLength)
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
                match PublicKey::from_bytes(bytes) {
                    Ok(t) => Ok(t),
                    Err(ProtoError::InvalidLength) => Err(de::Error::invalid_length(bytes.len(), &self)),
                    Err(ProtoError::InvalidValue(msg)) => Err(de::Error::invalid_value(de::Unexpected::Other(msg), &self)),
                    Err(err) => Err(de::Error::custom(err))
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
                    Err(ProtoError::InvalidLength) => Err(de::Error::invalid_length(bytes.len(), &self)),
                    Err(ProtoError::InvalidValue(msg)) => Err(de::Error::invalid_value(de::Unexpected::Other(msg), &self)),
                    Err(err) => Err(de::Error::custom(err))
                }
            }
        }

        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Short::from(self).fmt(f)
    }
}


pub struct Ed25519;

impl Signature3 for Ed25519 {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;
    type Signature = Signature;

    const NAME: &'static str = "Ed25519";

    fn sign(SecretKey(sk): &Self::PrivateKey, message: &[u8]) -> Self::Signature {
        Signature(sk.sign::<Sha3_512>(message))
    }

    fn verify(PublicKey(pk): &Self::PublicKey, Signature(sig): &Self::Signature, message: &[u8]) -> bool {
        pk.verify::<Sha3_512>(message, sig).is_ok()
    }
}
