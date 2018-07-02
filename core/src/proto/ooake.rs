//! One-pass OAKE protocol
//!
//! ```
//! A = g^a                             B = g^b
//!                 X = g^x
//!         --------------------------->
//!
//! Ka = B^(a + ex)
//!                                     Kb = A^b * X^(eb)
//!
//! e = H(IDa, A, IDb, B, X)
//! K = H(Ka) = H(Kb)
//! ```
//!
//! * [OAKE: a new family of implicitly authenticated diffie-hellman protocols](http://iiis.tsinghua.edu.cn/show-3800-1.html)

use rand::{ RngCore, CryptoRng };
use sha3::{ Sha3_512, Shake256 };
use digest::{ Input, ExtendableOutput, XofReader };
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use super::Error;


pub type SecretKey = Scalar;
pub type PublicKey = CompressedRistretto;
pub type Message = CompressedRistretto;

macro_rules! decompress {
    ( $e:expr ) => {
        match $e.decompress() {
            Some(e) => e,
            None => return Err(Error::Decompress)
        }
    }
}


pub fn send<ID: AsRef<str>, RNG: RngCore + CryptoRng>(
    rng: &mut RNG,
    (ref ida, a, aa): (ID, &SecretKey, &PublicKey),
    (ref idb, bb): (ID, &PublicKey),
    shared: &mut [u8]
) -> Result<Message, Error> {
    let x = Scalar::random(rng);
    let xx = (&x * &RISTRETTO_BASEPOINT_TABLE).compress();

    let mut hasher = Sha3_512::default();
    hasher.process(ida.as_ref().as_bytes());
    hasher.process(aa.as_bytes());
    hasher.process(idb.as_ref().as_bytes());
    hasher.process(bb.as_bytes());
    hasher.process(xx.as_bytes());
    let e = Scalar::from_hash(hasher);

    let bb = decompress!(bb);

    let k = bb * (a + e * x);

    let mut hasher = Shake256::default();
    hasher.process(k.compress().as_bytes());
    hasher.xof_result().read(shared);

    Ok(xx)
}

pub fn recv<ID: AsRef<str>>(
    (ref idb, b, bb): (ID, &SecretKey, &PublicKey),
    (ref ida, aa): (ID, &PublicKey),
    xx: &Message,
    shared: &mut [u8]
) -> Result<(), Error> {
    let mut hasher = Sha3_512::default();
    hasher.process(ida.as_ref().as_bytes());
    hasher.process(aa.as_bytes());
    hasher.process(idb.as_ref().as_bytes());
    hasher.process(bb.as_bytes());
    hasher.process(xx.as_bytes());
    let e = Scalar::from_hash(hasher);

    let aa = decompress!(aa);
    let xx = decompress!(xx);

    let k = aa * b + xx * (e * b);

    let mut hasher = Shake256::default();
    hasher.process(k.compress().as_bytes());
    hasher.xof_result().read(shared);

    Ok(())
}


#[test]
fn test_ooake() {
    use rand::thread_rng;

    let mut rng = thread_rng();

    let a_name = "alice@oake.ene";
    let a_sk = Scalar::random(&mut rng);
    let a_pk = (&a_sk * &RISTRETTO_BASEPOINT_TABLE).compress();
    let mut a_key = [0; 32];

    let b_name = "bob@oake.ene";
    let b_sk = Scalar::random(&mut rng);
    let b_pk = (&b_sk * &RISTRETTO_BASEPOINT_TABLE).compress();
    let mut b_key = [0; 32];

    let msg = send(
        &mut rng,
        (a_name, &a_sk, &a_pk),
        (b_name, &b_pk),
        &mut a_key
    ).unwrap();

    recv(
        (b_name, &b_sk, &b_pk),
        (a_name, &a_pk),
        &msg,
        &mut b_key
    ).unwrap();

    assert_ne!(a_key, [0; 32]);
    assert_eq!(a_key, b_key);
}
