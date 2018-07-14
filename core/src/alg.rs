use std::str::FromStr;


#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Signature {
    Ed25519
}

#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyExchange {
    RistrettoDH
}

#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
#[non_exhaustive]
pub enum Encrypt {
    Aes128Colm0
}


#[derive(Debug, Fail)]
#[fail(display = "unknown algorithm")]
pub struct UnknownAlgorithm;

impl FromStr for Encrypt {
    type Err = UnknownAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes128colm0" => Ok(Encrypt::Aes128Colm0),
            _ => Err(UnknownAlgorithm)
        }
    }
}
