macro_rules! decompress {
    ( $e:expr ) => {
        match $e.decompress() {
            Some(e) => e,
            None => return Err(Error::Decompress)
        }
    };
}

macro_rules! check {
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
