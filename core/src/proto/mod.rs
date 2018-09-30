//! Protocol implementation

pub mod ooake;
pub mod sigae;
pub mod sonly;

use serde_derive::{ Serialize, Deserialize };
use crate::define::{ KeyExchange, Signature };


/// OOAKE Message and Ciphertext
#[derive(Serialize, Deserialize)]
pub struct Ooake(
    ooake::Message,
    Vec<u8>
);

/// SIGAE Message and Ciphertext
#[derive(Serialize, Deserialize)]
pub struct Sigae<KEX: KeyExchange>(
    sigae::Message<KEX>,
    Vec<u8>
);

/// Signature Message
#[derive(Serialize, Deserialize)]
pub struct Sonly<SIG: Signature>(
    SIG::Signature
);
