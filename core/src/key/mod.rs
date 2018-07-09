pub mod ed25519;
pub mod ristretto_dh;


#[derive(Serialize, Deserialize)]
pub struct SecretKey {
    pub ed25519: Option<ed25519::SecretKey>,
    pub ristretto_dh: Option<ristretto_dh::SecretKey>
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    pub ed25519: Option<ed25519::PublicKey>,
    pub ristretto_dh: Option<ristretto_dh::PublicKey>
}
