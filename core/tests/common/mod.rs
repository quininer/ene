use serde::{ Serialize, Deserialize };
use serde_cbor::error::Error as CborError;
use ene_core::define::Serde;
use ene_core::error;


pub struct Cbor;

impl Serde for Cbor {
    type Error = CborError;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, error::Error<Self::Error>> {
        serde_cbor::to_vec(value)
            .map_err(|err| error::Error::Format(err.into()))
    }

    fn from_slice<'a, T: Deserialize<'a>>(slice: &'a [u8]) -> Result<T, error::Error<Self::Error>> {
        serde_cbor::from_slice(slice)
            .map_err(|err| error::Error::Format(err.into()))
    }
}
