use std::result;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Fail)]
#[non_exhaustive]
pub enum Error {
    #[fail(display = "Invalid value")]
    InvalidValue(&'static str),

    #[fail(display = "Invalid length")]
    InvalidLength,

    #[fail(display = "Ed25519 Decoding Error: {}", _0)]
    Ed25519(ed25519_dalek::DecodingError),

    #[fail(display = "Fail to pass verification")]
    VerificationFailed,

    #[fail(display = "{} algorithm does not support", _0)]
    Unsupported(&'static str),

    #[fail(display = "Rand Error: {}", _0)]
    Rand(rand::Error),

    #[fail(display = "Other Error: {}", _0)]
    Other(failure::Error)
}

impl From<ed25519_dalek::DecodingError> for Error {
    fn from(err: ed25519_dalek::DecodingError) -> Error {
        Error::Ed25519(err)
    }
}

impl From<rand::Error> for Error {
    fn from(err: rand::Error) -> Error {
        Error::Rand(err)
    }
}
