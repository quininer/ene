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
//!
//! ENE uses a AEAD variant of SIGMA. It uses AEAD instead of MAC to guarantee integrity.
//! Please note that this is not a SIGMA-I protocol variant.
//! Because it does not encrypt the IDs of both sides of the communication.
//!
//! In the Mail protocol, the IDs of both sides of the communication are usually public,
//! so there is no need to keep it secret.
//!
//! * [SIGMA](http://webee.technion.ac.il/~hugo/sigma.html)
//! * [Internet-Draft Ephemeral Diffie-Hellman Over COSE](https://tools.ietf.org/html/draft-selander-ace-cose-ecdhe-07#page-3)

use rand::{ Rng, CryptoRng };
use serde_derive::{ Serialize, Deserialize };
use sha3::{ Sha3_512, Shake256 };
use digest::{ Digest, Input, ExtendableOutput, XofReader };
use seckey::TempKey;
use crate::key::ed25519;
use crate::define::{ Packing, Signature, KeyExchange, AeadCipher };
use crate::error::ProtoError;


#[derive(Serialize, Deserialize)]
pub struct Message<KEX: KeyExchange> {
    m: KEX::Message,
    c: Vec<u8>
}

pub fn send<
    RNG: Rng + CryptoRng,
    SIG: Signature,
    KEX: KeyExchange,
>(
    rng: &mut RNG,
    aead: &dyn AeadCipher,
    (ida, sk): (&str, &SIG::PrivateKey),
    (idb, pk): (&str, &KEX::PublicKey),
    aad: &[u8],
    plaintext: &[u8],
    flag: bool
) -> Result<(Message<KEX>, Vec<u8>), ProtoError> {
    let mut kexkey = vec![0; KEX::SHARED_LENGTH];
    let mut kexkey = TempKey::from(&mut kexkey[..]);
    let mut aekey = vec![0; aead.key_length()];
    let mut aekey = TempKey::from(&mut aekey[..]);
    let mut nonce = vec![0; aead.nonce_length()];
    let ida = ida.as_bytes();
    let idb = idb.as_bytes();

    let m = KEX::exchange_to(rng, &mut kexkey, pk)?;
    let mut hasher = Shake256::default();
    hasher.process(b"SIGAE");
    hasher.process(SIG::NAME.as_bytes());
    hasher.process(KEX::NAME.as_bytes());
    hasher.process(&kexkey);
    let mut xof = hasher.xof_result();
    xof.read(&mut aekey);
    xof.read(&mut nonce);

    let mut hasher = Sha3_512::default();
    hasher.input(ida);
    hasher.input(&[0xff]);
    hasher.input(idb);
    pk.read_bytes(|bytes| hasher.input(bytes));
    m.read_bytes(|bytes| hasher.input(bytes));
    if flag {
        hasher.input(Sha3_512::digest(aad).as_slice());
        hasher.input(Sha3_512::digest(plaintext).as_slice());
    }
    let sig = SIG::sign(sk, hasher.result().as_slice());

    let mut id = Vec::with_capacity(ida.len() + idb.len() + 1);
    id.extend_from_slice(ida);
    id.push(0xff);
    id.extend_from_slice(idb);
    let mut c = vec![0; ed25519::Signature::BYTES_LENGTH + aead.tag_length()];
    sig.read_bytes(|sig| aead.seal(&aekey, &nonce, &id, &sig, &mut c))?;

    xof.read(&mut aekey);
    xof.read(&mut nonce);

    let mut c2 = vec![0; plaintext.len() + aead.tag_length()];
    aead.seal(&aekey, &nonce, aad, plaintext, &mut c2)?;

    Ok((Message { m, c }, c2))
}

pub fn recv<
    SIG: Signature,
    KEX: KeyExchange,
>(
    aead: &dyn AeadCipher,
    (idb, sk, pk): (&str, &KEX::PrivateKey, &KEX::PublicKey),
    (ida, pka): (&str, &SIG::PublicKey),
    Message { m, c }: &Message<KEX>,
    aad: &[u8],
    ciphertext: &[u8],
    flag: bool
) -> Result<Vec<u8>, ProtoError> {
    let mut kexkey = vec![0; KEX::SHARED_LENGTH];
    let mut kexkey = TempKey::from(&mut kexkey[..]);
    let mut aekey = vec![0; aead.key_length()];
    let mut aekey = TempKey::from(&mut aekey[..]);
    let mut nonce = vec![0; aead.nonce_length()];
    let ida = ida.as_bytes();
    let idb = idb.as_bytes();

    KEX::exchange_from(&mut kexkey, sk, m)?;
    let mut hasher = Shake256::default();
    hasher.process(b"SIGAE");
    hasher.process(SIG::NAME.as_bytes());
    hasher.process(KEX::NAME.as_bytes());
    hasher.process(&kexkey);
    let mut xof = hasher.xof_result();

    let mut id = Vec::with_capacity(ida.len() + idb.len() + 1);
    id.extend_from_slice(ida);
    id.push(0xff);
    id.extend_from_slice(idb);

    xof.read(&mut aekey);
    xof.read(&mut nonce);
    let mut sig = vec![0; c.len() - aead.tag_length()];
    aead.open(&aekey, &nonce, &id, c, &mut sig)?;
    let sig = SIG::Signature::from_bytes(&sig)?;

    xof.read(&mut aekey);
    xof.read(&mut nonce);
    let mut plaintext = vec![0; ciphertext.len() - aead.tag_length()];
    aead.open(&aekey, &nonce, aad, &ciphertext, &mut plaintext)?;

    let mut hasher = Sha3_512::default();
    hasher.input(ida);
    hasher.input(&[0xff]);
    hasher.input(idb);
    pk.read_bytes(|bytes| hasher.input(bytes));
    m.read_bytes(|bytes| hasher.input(bytes));
    if flag {
        hasher.input(Sha3_512::digest(aad).as_slice());
        hasher.input(Sha3_512::digest(&plaintext).as_slice());
    }
    if SIG::verify(pka, &sig, hasher.result().as_slice()) {
        Ok(plaintext)
    } else {
        Err(ProtoError::VerificationFailed(SIG::NAME))
    }
}

#[test]
fn test_proto_sigae() {
    use rand::{ Rng, thread_rng };
    use rand::distributions::Alphanumeric;
    use crate::aead::aes128colm0::Aes128Colm0;
    use crate::key::ristrettodh;

    let mut rng = thread_rng();

    let aad = rng.sample_iter(&Alphanumeric)
        .take(42)
        .fuse()
        .collect::<String>();
    let m = rng.sample_iter(&Alphanumeric)
        .take(1024)
        .fuse()
        .collect::<String>();

    let a_name = "alice@oake.ene";
    let a_sk = ed25519::SecretKey::generate(&mut rng);
    let a_pk = ed25519::PublicKey::from_secret(&a_sk);

    let b_name = "bob@oake.ene";
    let b_dhsk = ristrettodh::SecretKey::generate(&mut rng);
    let b_dhpk = ristrettodh::PublicKey::from_secret(&b_dhsk);

    let (msg, c) = send::<
        _,
        ed25519::Ed25519,
        ristrettodh::RistrettoDH,
    >(
        &mut rng,
        &Aes128Colm0,
        (a_name, &a_sk),
        (b_name, &b_dhpk),
        aad.as_bytes(),
        m.as_bytes(),
        false
    ).unwrap();

    let p = recv::<
        ed25519::Ed25519,
        ristrettodh::RistrettoDH,
    >(
        &Aes128Colm0,
        (b_name, &b_dhsk, &b_dhpk),
        (a_name, &a_pk),
        &msg,
        aad.as_bytes(),
        &c,
        false
    ).unwrap();

    assert_eq!(p, m.as_bytes());
}
