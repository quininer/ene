use std::path::PathBuf;
use structopt::clap::ArgGroup;
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
    Contact(Contact)
}

#[derive(Debug, StructOpt)]
#[structopt(raw(group = "arg_group(\"profile\")"))]
pub struct Profile {
    #[structopt(
        long = "init",
        group = "profile", requires = "id",
        display_order = 1
    )]
    pub init: bool,

    /// e.g. alice@core.ene
    #[structopt(long = "id", value_name = "ID", display_order = 1)]
    pub id: Option<String>,

    /// e.g. ed25519,ristrettodh
    #[structopt(short = "a", long = "algorithm", value_name = "STRING")]
    pub algorithm: Option<String>,

    /// e.g. aes128colm0
    #[structopt(short = "x", long = "encrypt-algorithm", value_name = "STRING")]
    pub encrypt: Option<alg::Encrypt>,

    #[structopt(
        short = "i", long = "import",
        value_name = "PATH",
        group = "profile",
        parse(from_os_str)
    )]
    pub import: Option<PathBuf>,

    #[structopt(
        short = "e", long = "export",
        value_name = "PATH",
        group = "profile",
        parse(from_os_str)
    )]
    pub export: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
#[structopt(raw(group = "arg_group(\"contact\")"))]
pub struct Contact {
    #[structopt(long = "list", group = "contact")]
    pub list: bool,

    #[structopt(name = "id", value_name = "ID")]
    pub id: Option<String>,

    #[structopt(short = "i", long = "import", parse(from_os_str), group = "contact")]
    pub import: Option<PathBuf>,

    #[structopt(
        short = "e", long = "export",
        requires = "id", group = "contact",
        parse(from_os_str)
    )]
    pub export: Option<PathBuf>,

    #[structopt(short = "d", long = "delete", requires = "id", group = "contact")]
    pub delete: bool,
}

fn arg_group(name: &'static str) -> ArgGroup<'static> {
    ArgGroup::with_name(name).required(true)
}
