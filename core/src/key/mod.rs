pub mod ed25519;
pub mod ristretto_dh;

use crate::format::Short;


#[derive(Serialize, Deserialize)]
pub struct SecretKey {
    pub ed25519: Option<ed25519::SecretKey>,
    pub ristretto_dh: Option<ristretto_dh::SecretKey>
}

#[derive(Default)]
#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    pub ed25519: Option<ed25519::PublicKey>,
    pub ristretto_dh: Option<ristretto_dh::PublicKey>
}

#[derive(Default)]
#[derive(Serialize, Deserialize)]
pub struct ShortPublicKey {
    pub ed25519: Option<Short>,
    pub ristretto_dh: Option<Short>
}
