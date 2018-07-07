#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Signature {
    Ed25519
}

#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyExchange {
    RistrettoDH
}

#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Encrypt {
    Aes128Colm0
}
