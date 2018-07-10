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

macro_rules! try_unwrap {
    ( $k:expr ; $alg:expr ) => {
        match $k {
            Some(k) => k,
            None => return Err(crate::error::Error::Unsupported($alg))
        }
    }
}
