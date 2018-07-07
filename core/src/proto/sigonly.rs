use sha3::Sha3_512;
use crate::key::ed25519;
use crate::Error;


pub type Message = ed25519::Signature;

pub fn send(
    ed25519::SecretKey(sk): &ed25519::SecretKey,
    plaintext: &[u8]
) -> Result<ed25519::Signature, Error> {
    let sig = sk.sign::<Sha3_512>(plaintext);
    Ok(ed25519::Signature(sig))
}

pub fn recv(
    ed25519::PublicKey(pk): &ed25519::PublicKey,
    ed25519::Signature(sig): &ed25519::Signature,
    plaintext: &[u8]
) -> Result<(), Error> {
    if pk.verify::<Sha3_512>(plaintext, sig) {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}
