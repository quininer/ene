use std::path::PathBuf;
use structopt::clap::ArgGroup;
use crate::core::alg::{ self, Protocol };


#[derive(Debug, StructOpt)]
#[structopt(name = "ene")]
pub enum Options {
    #[structopt(
        name = "profile", about = "Profile",
        raw(group = "arg_group(\"profile\")")
    )]
    Profile(Profile),

    #[structopt(
        name = "sendto", about = "SendTo",
        raw(group = "arg_group(\"target\")")
    )]
    SendTo(SendTo),

    #[structopt(
        name = "recvfrom", about = "RecvFrom",
        raw(group = "arg_group(\"target\")")
    )]
    RecvFrom(RecvFrom),

    #[structopt(
        name = "contact", about = "Contact",
        raw(group = "arg_group(\"contact\")")
    )]
    Contact(Contact)
}

#[derive(Debug, StructOpt)]
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
        short = "e", long = "export-public", alias = "export",
        value_name = "PATH",
        group = "profile",
        parse(from_os_str)
    )]
    pub export_public: Option<PathBuf>,

    #[structopt(
        long = "export-secret",
        value_name = "PATH",
        group = "profile",
        parse(from_os_str)
    )]
    pub export_secret: Option<PathBuf>,
}

#[derive(Debug, StructOpt)]
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

#[derive(Debug, StructOpt)]
pub struct SendTo {
    #[structopt(name = "id", value_name = "ID", group = "target")]
    pub target: Option<String>,

    #[structopt(
        short = "i", long = "input",
        value_name = "PATH",
        parse(from_os_str)
    )]
    pub input: PathBuf,

    #[structopt(
        short = "o", long = "output",
        value_name = "PATH",
        parse(from_os_str)
    )]
    pub output: Option<PathBuf>,

    #[structopt(
        short = "p", long = "protocol",
        value_name = "PROTOCOL",
        default_value = "ooake-ristrettodh-aes128colm0"
    )]
    pub protocol: Protocol,

    #[structopt(long = "associated-data", value_name = "STRING")]
    pub associated_data: Option<String>,

    #[structopt(long = "profile", value_name = "PATH", parse(from_os_str))]
    pub profile: Option<PathBuf>,

    #[structopt(
        long = "target-public",
        value_name = "PATH", group = "target",
        parse(from_os_str)
    )]
    pub target_public: Option<PathBuf>
}

#[derive(Debug, StructOpt)]
pub struct RecvFrom {
    #[structopt(name = "id", value_name = "ID", group = "target")]
    pub target: String,

    #[structopt(
        short = "i", long = "input",
        value_name = "PATH",
        parse(from_os_str)
    )]
    pub input: PathBuf,

    #[structopt(
        short = "o", long = "output",
        value_name = "PATH",
        parse(from_os_str)
    )]
    pub output: Option<PathBuf>,

    #[structopt(long = "associated-data", value_name = "STRING")]
    pub associated_data: Option<String>,

    #[structopt(short = "f", long = "force")]
    pub force: bool,

    #[structopt(long = "profile", value_name = "PATH", parse(from_os_str))]
    pub profile: Option<PathBuf>,

    #[structopt(
        long = "target-public",
        value_name = "PATH", group = "target",
        parse(from_os_str)
    )]
    pub target_public: Option<PathBuf>,
}

fn arg_group(name: &'static str) -> ArgGroup<'static> {
    ArgGroup::with_name(name).required(true)
}
