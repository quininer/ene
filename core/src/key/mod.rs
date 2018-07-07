pub mod ed25519;
pub mod ristretto_dh;


#[derive(Serialize, Deserialize)]
pub struct SecretKey {
    pub ed25519: ed25519::SecretKey,
    pub ristretto_dh: ristretto_dh::SecretKey
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    pub ed25519: ed25519::PublicKey,
    pub ristretto_dh: ristretto_dh::PublicKey
}
