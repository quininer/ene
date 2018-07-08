use std::hash::Hasher;
use siphasher::sip128::{ Hasher128, SipHasher };
use crate::key::ristretto_dh;
use crate::proto::{ ooake, sigae };
use crate::define::{ Packing, KeyExchange, Signature };


#[derive(Serialize, Deserialize)]
pub struct Short(pub u128);

#[derive(Serialize, Deserialize)]
pub struct Ooake(
    ristretto_dh::PublicKey,
    u128,
    ooake::Message,
    Vec<u8>
);

#[derive(Serialize, Deserialize)]
pub struct Sigae<SIG: Signature, KEX: KeyExchange>(
    SIG::PublicKey,
    u128,
    sigae::Message<KEX>,
    Vec<u8>
);

#[derive(Serialize, Deserialize)]
pub struct Sonly<SIG: Signature>(
    SIG::PublicKey,
    SIG::Signature,
    Vec<u8>
);

impl<'a, T: Packing> From<&'a T> for Short {
    fn from(t: &'a T) -> Short {
        let mut hasher = SipHasher::new();
        t.read_bytes(|bytes| hasher.write(bytes));
        let hash = hasher.finish128();
        Short(u128::from_bytes(hash.as_bytes()))
    }
}
