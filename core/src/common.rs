macro_rules! check {
    ( serde $e:expr ) => {
        if $e != [0; 32] {
            $e
        } else {
            return Err(serde::de::Error::custom("zero value"))
        }
    };
    ( $e:expr ) => {
        if $e != [0; 32] {
            $e
        } else {
            return Err(crate::error::ProtoError::InvalidValue("zero value"))
        }
    }
}

macro_rules! try_unwrap {
    ( $k:expr ; $alg:expr ) => {
        match $k {
            Some(k) => k,
            None => return Err(
                crate::error::Error::Parse(
                    crate::alg::ParseError::Unknown($alg.into())
                )
            )
        }
    }
}
