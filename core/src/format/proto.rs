use crate::key::ristretto_dh;
use crate::proto::{ ooake, sigae };
use crate::define::{ KeyExchange, Signature };


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
