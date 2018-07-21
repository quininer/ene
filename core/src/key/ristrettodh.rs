use std::fmt;
use rand::{ Rng, CryptoRng };
use sha3::{ Digest, Sha3_512 };
use serde::{ Deserialize, Deserializer };
use serde::de::{ self, Visitor };
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{ RistrettoPoint, CompressedRistretto };
use curve25519_dalek::scalar::Scalar;
use crate::define::{ Packing, KeyExchange };
use crate::error::ProtoError;


#[derive(Clone, Debug)]
#[derive(Serialize, Deserialize)]
pub struct SecretKey(pub(crate) Scalar, pub(crate) RistrettoPoint);

#[derive(Clone, Debug, Eq, PartialEq)]
#[derive(Serialize)]
pub struct PublicKey(pub(crate) RistrettoPoint);

#[derive(Clone, Debug)]
#[derive(Serialize)]
pub struct Message(pub(crate) RistrettoPoint);

impl SecretKey {
    pub fn generate<RNG: Rng + CryptoRng>(rng: &mut RNG) -> SecretKey {
        let sk = Scalar::random(rng);
        let pk = &sk * &RISTRETTO_BASEPOINT_TABLE;
        SecretKey(sk, pk)
    }
}

impl PublicKey {
    pub fn from_secret(SecretKey(_, pk): &SecretKey) -> PublicKey {
        PublicKey(pk.clone())
    }
}

macro_rules! de {
    ( $t:ident ) => {
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: Deserializer<'de>
            {
                struct PointVisitor;

                impl<'de> Visitor<'de> for PointVisitor {
                    type Value = $t;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("a valid point in Ristretto format")
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<$t, E>
                        where E: de::Error
                    {
                        match $t::from_bytes(v) {
                            Ok(t) => Ok(t),
                            Err(ProtoError::InvalidLength) => Err(de::Error::invalid_length(v.len(), &self)),
                            Err(ProtoError::InvalidValue(msg)) => Err(de::Error::invalid_value(de::Unexpected::Other(msg), &self)),
                            Err(err) => Err(de::Error::custom(err))
                        }
                    }
                }

                deserializer.deserialize_bytes(PointVisitor)
            }
        }
    }
}

de!(PublicKey);
de!(Message);


impl Packing for PublicKey {
    const BYTES_LENGTH: usize = 32;

    fn read_bytes<F, R>(&self, f: F) -> R
        where F: FnOnce(&[u8]) -> R
    {
        f(self.0.compress().as_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() == Self::BYTES_LENGTH {
            check!(bytes);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            CompressedRistretto(arr)
                .decompress()
                .map(PublicKey)
                .ok_or(ProtoError::InvalidValue("decompression failed"))
        } else {
            Err(ProtoError::InvalidLength)
        }
    }
}

impl Packing for Message {
    const BYTES_LENGTH: usize = 32;

    fn read_bytes<F, R>(&self, f: F) -> R
        where F: FnOnce(&[u8]) -> R
    {
        f(self.0.compress().as_bytes())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() == Self::BYTES_LENGTH {
            check!(bytes);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            CompressedRistretto(arr)
                .decompress()
                .map(Message)
                .ok_or(ProtoError::InvalidValue("decompression failed"))
        } else {
            Err(ProtoError::InvalidLength)
        }
    }
}


pub struct RistrettoDH;

impl KeyExchange for RistrettoDH {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;
    type Message = Message;

    const NAME: &'static str = "RistrettoDH";
    const SHARED_LENGTH: usize = 64;

    fn exchange_to<R: Rng + CryptoRng>(r: &mut R, sharedkey: &mut [u8], pk: &Self::PublicKey) -> Result<Self::Message, ProtoError> {
        let PublicKey(pk) = pk;
        let ek = Scalar::random(r);
        let m = &ek * &RISTRETTO_BASEPOINT_TABLE;

        let k = (ek * pk).compress();
        let k = Sha3_512::digest(k.as_bytes());
        sharedkey.copy_from_slice(k.as_slice());

        Ok(Message(m))
    }

    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, Message(m): &Self::Message) -> Result<(), ProtoError> {
        let SecretKey(sk, _) = sk;

        let k = (sk * m).compress();
        let k = Sha3_512::digest(k.as_bytes());
        sharedkey.copy_from_slice(k.as_slice());

        Ok(())
    }
}
