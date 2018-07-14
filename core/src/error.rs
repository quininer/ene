#[derive(Debug, Fail)]
#[non_exhaustive]
pub enum Error<E> {
    #[fail(display = "Core Error: {}", _0)]
    Core(CoreError),

    #[fail(display = "Rand Error: {}", _0)]
    Rand(rand::Error),

    #[fail(display = "{} algorithm does not support", _0)]
    Unsupported(&'static str),

    #[fail(display = "Format Error: {}", _0)]
    Format(E)
}

#[derive(Debug, Fail)]
#[non_exhaustive]
pub enum CoreError {
    #[fail(display = "Fail to pass verification: {}", _0)]
    VerificationFailed(&'static str),

    #[fail(display = "Invalid length")]
    InvalidLength,

    #[fail(display = "Invalid value: {}", _0)]
    InvalidValue(&'static str),

    #[fail(display = "Ed25519 Decoding Error: {}", _0)]
    Ed25519(ed25519_dalek::DecodingError)
}

impl From<ed25519_dalek::DecodingError> for CoreError {
    fn from(err: ed25519_dalek::DecodingError) -> CoreError {
        CoreError::Ed25519(err)
    }
}

impl<E> From<rand::Error> for Error<E> {
    fn from(err: rand::Error) -> Error<E> {
        Error::Rand(err)
    }
}

impl<E> From<CoreError> for Error<E> {
    fn from(err: CoreError) -> Error<E> {
        Error::Core(err)
    }
}
