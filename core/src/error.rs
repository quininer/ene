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
}

impl From<ed25519_dalek::DecodingError> for Error {
    fn from(err: ed25519_dalek::DecodingError) -> Error {
        Error::Ed25519(err)
    }
}
