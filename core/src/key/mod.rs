//! PublicKey Cryptography implementation

pub mod ed25519;
pub mod ristrettodh;

use crate::format::Short;


/// SecretKey Set
#[derive(Serialize, Deserialize)]
pub struct SecretKey {
    pub ed25519: Option<ed25519::SecretKey>,
    pub ristrettodh: Option<ristrettodh::SecretKey>
}

/// PublicKey Set
#[derive(Default)]
#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    pub ed25519: Option<ed25519::PublicKey>,
    pub ristrettodh: Option<ristrettodh::PublicKey>
}

/// Short PublicKey Set
#[derive(Debug, Default)]
#[derive(Serialize, Deserialize)]
pub struct ShortPublicKey {
    pub ed25519: Option<Short>,
    pub ristrettodh: Option<Short>
}

impl SecretKey {
    pub fn to_public(&self) -> PublicKey {
        PublicKey {
            ed25519: self.ed25519.as_ref().map(ed25519::PublicKey::from_secret),
            ristrettodh: self.ristrettodh.as_ref().map(ristrettodh::PublicKey::from_secret)
        }
    }
}

impl PublicKey {
    pub fn to_short(&self) -> ShortPublicKey {
        ShortPublicKey {
            ed25519: self.ed25519.as_ref().map(Short::from),
            ristrettodh: self.ristrettodh.as_ref().map(Short::from)
        }
    }
}
