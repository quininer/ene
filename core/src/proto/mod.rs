pub mod ooake;
pub mod sigae;
pub mod sonly;

use crate::define::{ KeyExchange, Signature };
use crate::alg;


#[derive(Clone, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Protocol {
    Sonly(alg::Signature),
    Ooake(alg::KeyExchange, alg::Encrypt),
    Sigae(bool, alg::Signature, alg::KeyExchange, alg::Encrypt)
}

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
