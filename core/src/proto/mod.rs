pub mod ooake;


#[derive(Debug, Fail)]
#[non_exhaustive]
#[must_use]
pub enum Error {
    #[fail(display = "Compressed point decompress error")]
    Decompress,

    #[fail(display = "Not allow zero value")]
    Zero,

    #[fail(display = "Invalid length")]
    Length
}
