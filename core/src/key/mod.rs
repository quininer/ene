pub mod ed25519;
pub mod ristrettodh;

use crate::format::Short;


#[derive(Serialize, Deserialize)]
pub struct SecretKey {
    pub ed25519: Option<ed25519::SecretKey>,
    pub ristrettodh: Option<ristrettodh::SecretKey>
}

#[derive(Default)]
#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    pub ed25519: Option<ed25519::PublicKey>,
    pub ristrettodh: Option<ristrettodh::PublicKey>
}

#[derive(Default)]
#[derive(Serialize, Deserialize)]
pub struct ShortPublicKey {
    pub ed25519: Option<Short>,
    pub ristrettodh: Option<Short>
}
