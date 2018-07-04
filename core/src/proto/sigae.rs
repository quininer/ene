//! One-pass SIGMA with AEAD protocol
//!
//! ```norun
//! Party A                                                 Party B
//!    |    X, AEAD(K; SIG(a; ID_A, ID_B, B, X); ID_A, ID_B)   |
//!    +------------------------------------------------------>|
//!    |                                                       |
//!
//! K = KX(x, B) = KX(b, X)
//! ```

use rand::{ Rng, CryptoRng };
use sha3::{ Sha3_512, Shake256 };
use digest::{ Digest, Input, ExtendableOutput, XofReader };
use crate::key::ed25519;
use crate::define::{ KeyExchange, AeadCipher };
use crate::common::Packing;
use crate::Error;


pub struct Message<KEX: KeyExchange> {
    m: KEX::Message,
    c: Vec<u8>
}

pub fn send<
    ID: AsRef<str>,
    RNG: Rng + CryptoRng,
    KEX: KeyExchange,
    AEAD: AeadCipher
>(
    rng: &mut RNG,
    (ref ida, ed25519::SecretKey(sk)): (ID, &ed25519::SecretKey),
    (ref idb, pk): (ID, &KEX::PublicKey),
    plaintext: &[u8],
) -> Result<(Message<KEX>, Vec<u8>), Error> {
    let mut kexkey = vec![0; KEX::SHARED_LENGTH];
    let mut aekey = vec![0; AEAD::KEY_LENGTH];
    let mut nonce = vec![0; AEAD::NONCE_LENGTH];
    let mut aekey2 = vec![0; AEAD::KEY_LENGTH];
    let mut nonce2 = vec![0; AEAD::NONCE_LENGTH];
    let ida = ida.as_ref().as_bytes();
    let idb = idb.as_ref().as_bytes();

    let m = KEX::exchange_to(rng, &mut kexkey, pk)?;
    let mut hasher = Shake256::default();
    hasher.process(&kexkey);
    let mut xof = hasher.xof_result();
    xof.read(&mut aekey);
    xof.read(&mut nonce);
    xof.read(&mut aekey2);
    xof.read(&mut nonce2);

    let mut hasher = Sha3_512::default();
    hasher.input(ida);
    hasher.input(&[0xff]);
    hasher.input(idb);
    pk.read_bytes(|bytes| hasher.input(bytes));
    m.read_bytes(|bytes| hasher.input(bytes));
    hasher.input(plaintext);
    let sig = sk.sign::<Sha3_512>(hasher.result().as_slice());

    let mut aad = Vec::with_capacity(ida.len() + idb.len() + 1);
    aad.extend_from_slice(ida);
    aad.push(0xff);
    aad.extend_from_slice(idb);
    let sig = sig.to_bytes();
    let mut c = vec![0; sig.len() + AEAD::TAG_LENGTH];
    AEAD::seal(&aekey, &nonce, &aad, &sig, &mut c)?;

    let mut c2 = vec![0; plaintext.len() + AEAD::TAG_LENGTH];
    AEAD::seal(&aekey2, &nonce2, &[], plaintext, &mut c2)?;

    Ok((Message { m, c }, c2))
}

pub fn recv<
    ID: AsRef<str>,
    RNG: Rng + CryptoRng,
    KEX: KeyExchange,
    AEAD: AeadCipher,
>(
    (ref idb, sk, pk): (ID, &KEX::PrivateKey, &KEX::PublicKey),
    (ref ida, ed25519::PublicKey(pkb)): (ID, &ed25519::PublicKey),
    Message { m, c }: &Message<KEX>,
    ciphertext: &[u8]
) -> Result<Vec<u8>, Error> {
    let mut kexkey = vec![0; KEX::SHARED_LENGTH];
    let mut aekey = vec![0; AEAD::KEY_LENGTH];
    let mut nonce = vec![0; AEAD::NONCE_LENGTH];
    let mut aekey2 = vec![0; AEAD::KEY_LENGTH];
    let mut nonce2 = vec![0; AEAD::NONCE_LENGTH];
    let ida = ida.as_ref().as_bytes();
    let idb = idb.as_ref().as_bytes();

    KEX::exchange_from(&mut kexkey, sk, m)?;
    let mut hasher = Shake256::default();
    hasher.process(&kexkey);
    let mut xof = hasher.xof_result();
    xof.read(&mut aekey);
    xof.read(&mut nonce);
    xof.read(&mut aekey2);
    xof.read(&mut nonce2);

    let mut aad = Vec::with_capacity(ida.len() + idb.len() + 1);
    aad.extend_from_slice(ida);
    aad.push(0xff);
    aad.extend_from_slice(idb);
    let mut sig = vec![0; c.len() - AEAD::TAG_LENGTH];
    AEAD::open(&aekey, &nonce, &aad, c, &mut sig)?;
    let ed25519::Signature(sig) = ed25519::Signature::from_bytes(&sig)?;

    let mut plaintext = vec![0; ciphertext.len() - AEAD::TAG_LENGTH];
    AEAD::open(&aekey2, &nonce2, &[], &ciphertext, &mut plaintext)?;

    let mut hasher = Sha3_512::default();
    hasher.input(ida);
    hasher.input(&[0xff]);
    hasher.input(idb);
    pk.read_bytes(|bytes| hasher.input(bytes));
    m.read_bytes(|bytes| hasher.input(bytes));
    hasher.input(&plaintext);

    if pkb.verify::<Sha3_512>(hasher.result().as_slice(), &sig) {
        Ok(plaintext)
    } else {
        Err(Error::VerificationFailed)
    }
}