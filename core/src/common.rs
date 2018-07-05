macro_rules! check {
    ( serde $e:expr ) => {
        if subtle::ConstantTimeEq::ct_eq($e, &[0; 32]).unwrap_u8() != 1 {
            $e
        } else {
            return Err(serde::de::Error::custom("not allow zero value"))
        }
    };
    ( $e:expr ) => {
        if subtle::ConstantTimeEq::ct_eq($e, &[0; 32]).unwrap_u8() != 1 {
            $e
        } else {
            return Err(Error::Zero)
        }
    }
}

pub trait Packing: Sized {
    const BYTES_LENGTH: usize;

    fn read_bytes<F: FnOnce(&[u8])>(&self, f: F);
}
