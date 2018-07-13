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
use crate::define::{ Packing, Signature, KeyExchange, AeadCipher };
use crate::error;


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
    aead: &AeadCipher,
    (ida, sk): (&str, &SIG::PrivateKey),
    (idb, pk): (&str, &KEX::PublicKey),
    aad: &[u8],
    plaintext: &[u8],
    flag: bool
) -> error::Result<(Message<KEX>, Vec<u8>)> {
    let mut kexkey = vec![0; KEX::SHARED_LENGTH];
    let mut aekey = vec![0; aead.key_length()];
    let mut nonce = vec![0; aead.nonce_length()];
    let ida = ida.as_bytes();
    let idb = idb.as_bytes();

    let m = KEX::exchange_to(rng, &mut kexkey, pk)?;
    let mut hasher = Shake256::default();
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
    if !flag {
        hasher.input(aad);
        hasher.input(&[0xff]);
        hasher.input(plaintext);
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
    aead: &AeadCipher,
    (idb, sk, pk): (&str, &KEX::PrivateKey, &KEX::PublicKey),
    (ida, pka): (&str, &SIG::PublicKey),
    Message { m, c }: &Message<KEX>,
    aad: &[u8],
    ciphertext: &[u8],
    flag: bool
) -> error::Result<Vec<u8>> {
    let mut kexkey = vec![0; KEX::SHARED_LENGTH];
    let mut aekey = vec![0; aead.key_length()];
    let mut nonce = vec![0; aead.nonce_length()];
    let ida = ida.as_bytes();
    let idb = idb.as_bytes();

    KEX::exchange_from(&mut kexkey, sk, m)?;
    let mut hasher = Shake256::default();
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
    if !flag {
        hasher.input(aad);
        hasher.input(&[0xff]);
        hasher.input(&plaintext);
    }
    if SIG::verify(pka, &sig, hasher.result().as_slice()) {
        Ok(plaintext)
    } else {
        Err(error::Error::VerificationFailed)
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
