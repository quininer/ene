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
//! The OAKE protocol family is designed by Andrew Yao,
//! which is superior to HMQV in many aspects.
//!
//! ENE used a one-pass variants of protocol mentioned in the appendix to the OAKE paper.
//!
//! * [OAKE: a new family of implicitly authenticated diffie-hellman protocols](http://iiis.tsinghua.edu.cn/show-3800-1.html)

use rand::{ RngCore, CryptoRng };
use sha3::{ Sha3_512, Shake256 };
use digest::{ Input, ExtendableOutput, XofReader };
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use crate::key::ristrettodh::{ self, SecretKey, PublicKey };
use crate::define::AeadCipher;
use crate::error::ProtoError;


pub type Message = ristrettodh::Message;

pub fn send<RNG: RngCore + CryptoRng>(
    rng: &mut RNG,
    aead: &AeadCipher,
    (ida, SecretKey(a, aa)): (&str, &SecretKey),
    (idb, PublicKey(bb)): (&str, &PublicKey),
    aad: &[u8],
    plaintext: &[u8]
) -> Result<(Message, Vec<u8>), ProtoError> {
    let mut aekey = vec![0; aead.key_length()];
    let mut nonce = vec![0; aead.nonce_length()];

    let x = Scalar::random(rng);
    let xx = &x * &RISTRETTO_BASEPOINT_TABLE;

    let mut hasher = Sha3_512::default();
    hasher.process(ida.as_bytes());
    hasher.process(aa.compress().as_bytes());
    hasher.process(idb.as_bytes());
    hasher.process(bb.compress().as_bytes());
    hasher.process(xx.compress().as_bytes());
    let e = Scalar::from_hash(hasher);

    let k = bb * (a + e * x);

    let mut hasher = Shake256::default();
    hasher.process(k.compress().as_bytes());
    let mut xof = hasher.xof_result();
    xof.read(&mut aekey);
    xof.read(&mut nonce);

    let mut ciphertext = vec![0; plaintext.len() + aead.tag_length()];
    aead.seal(&aekey, &nonce, aad, plaintext, &mut ciphertext)?;

    Ok((ristrettodh::Message(xx), ciphertext))
}

pub fn recv(
    aead: &AeadCipher,
    (idb, SecretKey(b, bb)): (&str, &SecretKey),
    (ida, PublicKey(aa)): (&str, &PublicKey),
    ristrettodh::Message(xx): &Message,
    aad: &[u8],
    ciphertext: &[u8]
) -> Result<Vec<u8>, ProtoError> {
    let mut aekey = vec![0; aead.key_length()];
    let mut nonce = vec![0; aead.nonce_length()];

    let mut hasher = Sha3_512::default();
    hasher.process(ida.as_bytes());
    hasher.process(aa.compress().as_bytes());
    hasher.process(idb.as_bytes());
    hasher.process(bb.compress().as_bytes());
    hasher.process(xx.compress().as_bytes());
    let e = Scalar::from_hash(hasher);

    let k = aa * b + xx * (e * b);

    let mut hasher = Shake256::default();
    hasher.process(k.compress().as_bytes());
    let mut xof = hasher.xof_result();
    xof.read(&mut aekey);
    xof.read(&mut nonce);

    let mut plaintext = vec![0; ciphertext.len() - aead.tag_length()];
    aead.open(&aekey, &nonce, aad, ciphertext, &mut plaintext)?;

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
        .collect::<String>();
    let aad = rng.sample_iter(&Alphanumeric)
        .take(42)
        .collect::<String>();

    let a_name = "alice@oake.ene";
    let a_sk = SecretKey::generate(&mut rng);
    let a_pk = PublicKey::from_secret(&a_sk);

    let b_name = "bob@oake.ene";
    let b_sk = SecretKey::generate(&mut rng);
    let b_pk = PublicKey::from_secret(&b_sk);

    let (msg, c) = send(
        &mut rng,
        &Aes128Colm0,
        (a_name, &a_sk),
        (b_name, &b_pk),
        aad.as_bytes(),
        m.as_bytes()
    ).unwrap();

    let p = recv(
        &Aes128Colm0,
        (b_name, &b_sk),
        (a_name, &a_pk),
        &msg,
        aad.as_bytes(),
        &c
    ).unwrap();

    assert_eq!(p, m.as_bytes());
}
