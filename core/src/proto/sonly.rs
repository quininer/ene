use sha3::{ Digest, Sha3_512 };
use crate::define::Signature;
use crate::error::ProtoError;


pub type Message<SIG> = <SIG as Signature>::Signature;

pub fn send<SIG: Signature>(
    (id, sk): (&str, &SIG::PrivateKey),
    aad: &[u8],
    message: &[u8]
) -> SIG::Signature {
    let mut hasher = Sha3_512::default();
    hasher.input(id.as_bytes());
    hasher.input(&[0xff]);
    hasher.input(Sha3_512::digest(aad).as_slice());
    hasher.input(message);
    SIG::sign(sk, hasher.result().as_slice())
}

pub fn recv<SIG: Signature>(
    (id, pk): (&str, &SIG::PublicKey),
    sig: &SIG::Signature,
    aad: &[u8],
    message: &[u8]
) -> Result<(), ProtoError> {
    let mut hasher = Sha3_512::default();
    hasher.input(id.as_bytes());
    hasher.input(&[0xff]);
    hasher.input(Sha3_512::digest(aad).as_slice());
    hasher.input(message);
    if SIG::verify(pk, sig, hasher.result().as_slice()) {
        Ok(())
    } else {
        Err(ProtoError::VerificationFailed(SIG::NAME))
    }
}


#[test]
fn test_proto_sonly() {
    use rand::{ Rng, thread_rng };
    use rand::distributions::Alphanumeric;
    use crate::key::ed25519;

    let mut rng = thread_rng();

    let m = rng.sample_iter(&Alphanumeric)
        .take(1024)
        .collect::<String>();
    let aad = rng.sample_iter(&Alphanumeric)
        .take(42)
        .collect::<String>();

    let a_name = "alice@oake.ene";
    let a_sk = ed25519::SecretKey::generate(&mut rng);
    let a_pk = ed25519::PublicKey::from_secret(&a_sk);

    let msg = send::<ed25519::Ed25519>(
        (a_name, &a_sk),
        aad.as_bytes(),
        m.as_bytes()
    );

    recv::<ed25519::Ed25519>(
        (a_name, &a_pk),
        &msg,
        aad.as_bytes(),
        m.as_bytes()
    ).unwrap();
}
