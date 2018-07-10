use crate::define::Signature;
use crate::error;


pub type Message<SIG> = <SIG as Signature>::Signature;

pub fn send<SIG: Signature>(sk: &SIG::PrivateKey, message: &[u8]) -> SIG::Signature {
    SIG::sign(sk, message)
}

pub fn recv<SIG: Signature>(
    pk: &SIG::PublicKey,
    sig: &SIG::Signature,
    message: &[u8]
) -> error::Result<()> {
    if SIG::verify(pk, sig, message) {
        Ok(())
    } else {
        Err(error::Error::VerificationFailed)
    }
}
