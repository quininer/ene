use crate::error;


macro_rules! check {
    ( serde $e:expr ) => {
        if subtle::ConstantTimeEq::ct_eq($e, &[0; 32]).unwrap_u8() != 1 {
            $e
        } else {
            return Err(serde::de::Error::custom("Invalid value"))
        }
    };
    ( $e:expr ) => {
        if subtle::ConstantTimeEq::ct_eq($e, &[0; 32]).unwrap_u8() != 1 {
            $e
        } else {
            return Err(error::Error::InvalidValue("zero value"))
        }
    }
}

pub trait Packing: Sized {
    const BYTES_LENGTH: usize;

    fn read_bytes<F, R>(&self, f: F) -> R
        where F: FnOnce(&[u8]) -> R;

    fn from_bytes(bytes: &[u8]) -> error::Result<Self>;
}
