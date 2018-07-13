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
