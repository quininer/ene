pub mod ooake;
pub mod sigae;
pub mod sonly;

use crate::define::{ KeyExchange, Signature };


#[derive(Serialize, Deserialize)]
pub struct Ooake(
    ooake::Message,
    Vec<u8>
);

#[derive(Serialize, Deserialize)]
pub struct Sigae<KEX: KeyExchange>(
    sigae::Message<KEX>,
    Vec<u8>
);

#[derive(Serialize, Deserialize)]
pub struct Sonly<SIG: Signature>(
    SIG::Signature
);
