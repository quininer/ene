use std::path::PathBuf;
use crate::core::alg;


#[derive(Debug, StructOpt)]
#[structopt(name = "ene")]
pub enum Options {
    #[structopt(name = "profile", about = "Profile")]
    Profile(Profile),

    #[structopt(name = "sendto", about = "SendTo")]
    SendTo,

    #[structopt(name = "recvfrom", about = "RecvFrom")]
    RecvFrom,

    #[structopt(name = "contact", about = "Contact")]
    Contact
}

#[derive(Debug, StructOpt)]
pub struct Profile {
    #[structopt(
        long = "init",
        conflicts_with = "import", conflicts_with = "export",
        requires = "id",
        display_order = 1
    )]
    pub init: bool,

    #[structopt(long = "id")]
    pub id: Option<String>,

    #[structopt(short = "a", long = "algorithm")]
    pub algorithm: Option<String>,

    #[structopt(short = "e", long = "encrypt-algorithm")]
    pub encrypt: Option<alg::Encrypt>,

    #[structopt(
        long = "import",
        conflicts_with = "export",
        parse(from_os_str)
    )]
    pub import: Option<PathBuf>,

    #[structopt(
        long = "export",
        conflicts_with = "import",
        parse(from_os_str)
    )]
    pub export: Option<PathBuf>,
}
