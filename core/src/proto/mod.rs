pub mod ooake;
pub mod sigae;
pub mod sonly;

pub mod alg {
    #[derive(Clone, Copy, Debug)]
    #[derive(Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum Signature {
        Ed25519
    }

    #[derive(Clone, Copy, Debug)]
    #[derive(Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum KeyExchange {
        RistrettoDH
    }

    #[derive(Clone, Copy, Debug)]
    #[derive(Serialize, Deserialize)]
    #[non_exhaustive]
    pub enum Encrypt {
        Aes128Colm0
    }
}

use crate::define::{ KeyExchange, Signature };


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
