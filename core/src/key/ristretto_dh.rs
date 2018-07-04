use rand::{ Rng, CryptoRng };
use sha3::{ Digest, Sha3_512 };
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use crate::define::KeyExchange;
use crate::common::Packing;
use crate::Error;

pub struct SecretKey(Scalar);
pub struct PublicKey(CompressedRistretto);
pub struct Message(CompressedRistretto);

pub struct RistrettoDH;

impl Packing for PublicKey {
    const BYTES_LENGTH: usize = 32;

    fn read_bytes<F: FnOnce(&[u8])>(&self, f: F) {
        f(self.0.as_bytes());
    }
}

impl Packing for Message {
    const BYTES_LENGTH: usize = 32;

    fn read_bytes<F: FnOnce(&[u8])>(&self, f: F) {
        f(self.0.as_bytes())
    }
}

impl KeyExchange for RistrettoDH {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;
    type Message = Message;

    const SHARED_LENGTH: usize = 64;

    fn exchange_to<R: Rng + CryptoRng>(r: &mut R, sharedkey: &mut [u8], pk: &Self::PublicKey) -> Result<Self::Message, Error> {
        let PublicKey(pk) = pk;
        let pk = decompress!(pk);
        let ek = Scalar::random(r);
        let m = (&ek * &RISTRETTO_BASEPOINT_TABLE).compress();

        let k = (ek * pk).compress();
        let k = Sha3_512::digest(k.as_bytes());
        sharedkey.copy_from_slice(k.as_slice());

        Ok(Message(m))
    }

    fn exchange_from(sharedkey: &mut [u8], sk: &Self::PrivateKey, Message(m): &Self::Message) -> Result<(), Error> {
        let SecretKey(sk) = sk;
        let m = decompress!(m);

        let k = (sk * m).compress();
        let k = Sha3_512::digest(k.as_bytes());
        sharedkey.copy_from_slice(k.as_slice());

        Ok(())
    }
}
