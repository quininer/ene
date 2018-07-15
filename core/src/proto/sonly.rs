use crate::define::Signature;
use crate::error::ProtoError;


pub type Message<SIG> = <SIG as Signature>::Signature;

pub fn send<SIG: Signature>(sk: &SIG::PrivateKey, message: &[u8]) -> SIG::Signature {
    SIG::sign(sk, message)
}

pub fn recv<SIG: Signature>(
    pk: &SIG::PublicKey,
    sig: &SIG::Signature,
    message: &[u8]
) -> Result<(), ProtoError> {
    if SIG::verify(pk, sig, message) {
        Ok(())
    } else {
        Err(ProtoError::VerificationFailed(SIG::NAME))
    }
}
