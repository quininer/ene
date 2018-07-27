use std::fmt;
use rand::{ Rng, CryptoRng };
use serde::{ Serialize, Serializer, Deserialize, Deserializer };
use serde::de::{ self, Visitor };
use sarkara::kex::{ CheckedExchange, KeyExchange as KeyExchange2, kyber };
use sarkara::Packing as _;
use crate::define::{ Packing, KeyExchange };
use crate::error::ProtoError;


#[derive(Serialize, Deserialize)]
pub struct SecretKey(pub(crate) kyber::PrivateKey, pub(crate) kyber::PublicKey);
#[derive(Serialize, Deserialize)]
pub struct PublicKey(pub(crate) kyber::PublicKey);
#[derive(Serialize, Deserialize)]
pub struct Message(pub(crate) kyber::Message);

impl SecretKey {
    pub fn generate<RNG: Rng + CryptoRng>(rng: &mut RNG) -> SecretKey {
        let (sk, pk) = kyber::Kyber::keypair(rng);
        SecretKey(sk, pk)
    }
}

impl PublicKey {
    pub fn from_secret(SecretKey(_, pk): &SecretKey) -> PublicKey {
        PublicKey(pk.read_bytes(kyber::PublicKey::from_bytes))
    }
}

macro_rules! packing {
    ( $t:ident ) => {
        impl Packing for $t {
            const BYTES_LENGTH: usize = kyber::$t::BYTES_LENGTH;

            fn read_bytes<F, R>(&self, f: F) -> R
                where F: FnOnce(&[u8]) -> R
            {
                self.0.read_bytes(f)
            }

            fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
                if bytes.len() == Self::BYTES_LENGTH {
                    Ok($t(kyber::$t::from_bytes(bytes)))
                } else {
                    Err(ProtoError::InvalidLength)
                }
            }
        }
    }
}

packing!(PublicKey);
packing!(Message);
