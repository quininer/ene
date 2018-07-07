//! One-pass OAKE protocol
//!
//! ```norun
//! Party A                                                 Party B
//!    |                            X                          |
//!    +------------------------------------------------------>|
//!    |                                                       |
//!
//! K_A = B^(a + ex)                                        K_B = A^b * X^(eb)
//!
//! e = H(ID_A, A, ID_B, B, X)
//! K = H(K_A) = H(K_B)
//! ```
//!
//! * [OAKE: a new family of implicitly authenticated diffie-hellman protocols](http://iiis.tsinghua.edu.cn/show-3800-1.html)

use rand::{ RngCore, CryptoRng };
use sha3::{ Sha3_512, Shake256 };
use digest::{ Input, ExtendableOutput, XofReader };
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use crate::key::ristretto_dh::{ self, SecretKey, PublicKey };
use crate::define::AeadCipher;
use crate::Error;


pub type Message = ristretto_dh::Message;

pub fn send<
    ID: AsRef<str>,
    RNG: RngCore + CryptoRng,
    AEAD: AeadCipher
>(
    rng: &mut RNG,
    (ref ida, SecretKey(a, PublicKey(aa))): (ID, &SecretKey),
    (ref idb, PublicKey(bb)): (ID, &PublicKey),
    plaintext: &[u8]
) -> Result<(Message, Vec<u8>), Error> {
    let mut aekey = vec![0; AEAD::KEY_LENGTH];
    let mut nonce = vec![0; AEAD::NONCE_LENGTH];

    let x = Scalar::random(rng);
    let xx = &x * &RISTRETTO_BASEPOINT_TABLE;

    let mut hasher = Sha3_512::default();
    hasher.process(ida.as_ref().as_bytes());
    hasher.process(aa.compress().as_bytes());
    hasher.process(idb.as_ref().as_bytes());
    hasher.process(bb.compress().as_bytes());
    hasher.process(xx.compress().as_bytes());
    let e = Scalar::from_hash(hasher);

    let k = bb * (a + e * x);

    let mut hasher = Shake256::default();
    hasher.process(k.compress().as_bytes());
    let mut xof = hasher.xof_result();
    xof.read(&mut aekey);
    xof.read(&mut nonce);

    let mut ciphertext = vec![0; plaintext.len() + AEAD::TAG_LENGTH];
    AEAD::seal(&aekey, &nonce, &[], plaintext, &mut ciphertext)?;

    Ok((ristretto_dh::Message(xx), ciphertext))
}

pub fn recv<
    ID: AsRef<str>,
    AEAD: AeadCipher
>(
    (ref idb, SecretKey(b, PublicKey(bb))): (ID, &SecretKey),
    (ref ida, PublicKey(aa)): (ID, &PublicKey),
    ristretto_dh::Message(xx): &Message,
    ciphertext: &[u8]
) -> Result<Vec<u8>, Error> {
    let mut aekey = vec![0; AEAD::KEY_LENGTH];
    let mut nonce = vec![0; AEAD::NONCE_LENGTH];

    let mut hasher = Sha3_512::default();
    hasher.process(ida.as_ref().as_bytes());
    hasher.process(aa.compress().as_bytes());
    hasher.process(idb.as_ref().as_bytes());
    hasher.process(bb.compress().as_bytes());
    hasher.process(xx.compress().as_bytes());
    let e = Scalar::from_hash(hasher);

    let k = aa * b + xx * (e * b);

    let mut hasher = Shake256::default();
    hasher.process(k.compress().as_bytes());
    let mut xof = hasher.xof_result();
    xof.read(&mut aekey);
    xof.read(&mut nonce);

    let mut plaintext = vec![0; ciphertext.len() - AEAD::TAG_LENGTH];
    AEAD::open(&aekey, &nonce, &[], ciphertext, &mut plaintext)?;

    Ok(plaintext)
}


#[test]
fn test_proto_ooake() {
    use rand::{ Rng, thread_rng };
    use rand::distributions::Alphanumeric;
    use crate::aead::aes128colm0::Aes128Colm0;

    let mut rng = thread_rng();

    let m = rng.sample_iter(&Alphanumeric)
        .take(1024)
        .fuse()
        .collect::<String>();

    let a_name = "alice@oake.ene";
    let a_sk = SecretKey::generate(&mut rng);
    let a_pk = a_sk.as_public();

    let b_name = "bob@oake.ene";
    let b_sk = SecretKey::generate(&mut rng);
    let b_pk = b_sk.as_public();

    let (msg, c) = send::<_, _, Aes128Colm0>(
        &mut rng,
        (a_name, &a_sk),
        (b_name, b_pk),
        m.as_bytes()
    ).unwrap();

    let p = recv::<_, Aes128Colm0>(
        (b_name, &b_sk),
        (a_name, a_pk),
        &msg,
        &c
    ).unwrap();

    assert_eq!(p, m.as_bytes());
}
