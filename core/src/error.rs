use std::borrow::Cow;
use std::option::NoneError;


#[derive(Debug, Fail)]
pub enum Error<E> {
    #[fail(display = "Protocol Error: {}", _0)]
    Proto(ProtoError),

    #[fail(display = "Rand Error: {}", _0)]
    Rand(rand::Error),

    #[fail(display = "Parse Error: {}", _0)]
    Parse(ParseError),

    #[fail(display = "Format Error: {}", _0)]
    Format(E)
}

#[derive(Debug, Fail)]
pub enum ProtoError {
    #[fail(display = "Fail to pass verification: {}", _0)]
    VerificationFailed(&'static str),

    #[fail(display = "Invalid length")]
    InvalidLength,

    #[fail(display = "Invalid value: {}", _0)]
    InvalidValue(&'static str),

    #[fail(display = "Ed25519 Signature Error: {}", _0)]
    Ed25519(ed25519_dalek::SignatureError)
}

#[derive(Debug, Fail)]
pub enum ParseError {
    #[fail(display = "Unknown algorithm: {}", _0)]
    Unknown(Cow<'static, str>),

    #[fail(display = "Unexpected end")]
    UnexpectedEnd,

    #[fail(display = "Not available: {}", _0)]
    NotAvailable(Cow<'static, str>)
}

impl<E> From<rand::Error> for Error<E> {
    fn from(err: rand::Error) -> Error<E> {
        Error::Rand(err)
    }
}

impl<E> From<ProtoError> for Error<E> {
    fn from(err: ProtoError) -> Error<E> {
        Error::Proto(err)
    }
}

impl From<ed25519_dalek::SignatureError> for ProtoError {
    fn from(err: ed25519_dalek::SignatureError) -> ProtoError {
        ProtoError::Ed25519(err)
    }
}

impl From<NoneError> for ParseError {
    fn from(_: NoneError) -> ParseError {
        ParseError::UnexpectedEnd
    }
}
