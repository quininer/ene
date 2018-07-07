use crate::key::{ ed25519, ristretto_dh };
use crate::proto::{ ooake, sigae };
use crate::define::KeyExchange;


#[derive(Serialize, Deserialize)]
pub struct Ooake(
    ristretto_dh::PublicKey,
    u128,
    ooake::Message,
    Vec<u8>
);

#[derive(Serialize, Deserialize)]
pub struct Sigae<KEX: KeyExchange>(
    ed25519::PublicKey,
    u128,
    sigae::Message<KEX>,
    Vec<u8>
);

#[derive(Serialize, Deserialize)]
pub struct SigOnly(
    ed25519::PublicKey,
    ed25519::Signature,
    Vec<u8>
);
