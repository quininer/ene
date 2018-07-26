pub mod ed25519;
pub mod ristrettodh;

use crate::format::Short;
use crate::define::{ Signature, KeyExchange };
use self::ed25519::Ed25519;
use self::ristrettodh::RistrettoDH;


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

    pub fn contains<E, F>(&self, pk: &PublicKey, mut f: F)
        -> Result<bool, E>
        where F: FnMut(&'static str, Short, Short) -> Result<(), E>
    {
        let mut flag = true;

        macro_rules! check {
            ( $name:expr, $pk:expr, $pack_pk:expr ) => {
                if let (Some(pk), Some(pack_pk)) = ($pk, $pack_pk) {
                    if pk != pack_pk {
                        f($name, Short::from(pk), Short::from(pack_pk))?;
                        flag &= false;
                    }
                }
            }
        }

        check!(Ed25519::NAME, &self.ed25519, &pk.ed25519);
        check!(RistrettoDH::NAME, &self.ristrettodh, &pk.ristrettodh);

        Ok(flag)
    }
}

impl ShortPublicKey {
    pub fn contains<E, F>(&self, pk: &ShortPublicKey, mut f: F)
        -> Result<bool, E>
        where F: FnMut(&'static str, Short, Short) -> Result<(), E>
    {
        let mut flag = true;

        macro_rules! check {
            ( $name:expr, $pk:expr, $pack_pk:expr ) => {
                if let (Some(pk), Some(pack_pk)) = ($pk, $pack_pk) {
                    if pk != pack_pk {
                        f($name, pk, pack_pk)?;
                        flag &= false;
                    }
                }
            }
        }

        check!(Ed25519::NAME, self.ed25519, pk.ed25519);
        check!(RistrettoDH::NAME, self.ristrettodh, pk.ristrettodh);

        Ok(flag)
    }
}
