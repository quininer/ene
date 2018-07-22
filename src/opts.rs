use std::path::PathBuf;
use structopt::clap::ArgGroup;
use crate::core::alg::{ self, Protocol };


#[derive(Debug, StructOpt)]
#[structopt(name = "ene")]
pub struct Options {
    #[structopt(subcommand)]
    pub subcommand: SubCommand,

    #[structopt(short = "c", long = "color", value_name = "MODE", default_value = "auto")]
    pub color: ColorChoice
}

arg_enum! {
    #[derive(PartialEq, Debug)]
    pub enum ColorChoice {
        Always,
        AlwaysAnsi,
        Auto,
        Never
    }
}

#[derive(Debug, StructOpt)]
pub enum SubCommand {
    #[structopt(
        name = "profile", about = "Profile", display_order = 1,
        raw(group = "arg_group(\"profile\")")
    )]
    Profile(Profile),

    #[structopt(
        name = "contact", about = "Contact", display_order = 2,
        raw(group = "arg_group(\"contact\")")
    )]
    Contact(Contact),

    #[structopt(
        name = "sendto", about = "SendTo", display_order = 3,
        raw(group = "arg_group(\"recipient\")")
    )]
    SendTo(SendTo),

    #[structopt(
        name = "recvfrom", about = "RecvFrom", display_order = 4,
        raw(group = "arg_group(\"sender\")")
    )]
    RecvFrom(RecvFrom)
}

#[derive(Debug, StructOpt)]
pub struct Profile {
    #[structopt(
        long = "init",
        group = "profile", requires = "id",
        display_order = 1
    )]
    pub init: bool,

    #[structopt(name = "id", value_name = "ID")]
    pub id: Option<String>,

    #[structopt(short = "a", long = "algorithm", value_name = "STRING")]
    pub algorithm: Option<String>,

    #[structopt(short = "X", long = "encrypt-cipher", value_name = "CIPHER")]
    pub encrypt: Option<alg::Encrypt>,

    #[structopt(
        short = "i", long = "import",
        value_name = "PATH", group = "profile",
        parse(from_os_str)
    )]
    pub import: Option<PathBuf>,

    #[structopt(
        short = "e", long = "export-pubkey", alias = "export",
        value_name = "PATH", group = "profile",
        parse(from_os_str)
    )]
    pub export_pubkey: Option<PathBuf>,

    #[structopt(
        short = "E", long = "export-privkey",
        value_name = "PATH", group = "profile",
        parse(from_os_str)
    )]
    pub export_privkey: Option<PathBuf>,
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
    #[structopt(name = "id", value_name = "ID", group = "recipient")]
    pub recipient: Option<String>,

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

    #[structopt(short = "A", long = "associated-data", value_name = "STRING")]
    pub associated_data: Option<String>,

    #[structopt(long = "profile", value_name = "PATH", parse(from_os_str))]
    pub profile: Option<PathBuf>,

    #[structopt(
        long = "recipient-file",
        value_name = "PATH", group = "recipient",
        parse(from_os_str)
    )]
    pub recipient_file: Option<PathBuf>
}

#[derive(Debug, StructOpt)]
pub struct RecvFrom {
    #[structopt(name = "id", value_name = "ID", group = "sender")]
    pub sender: Option<String>,

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

    #[structopt(short = "A", long = "associated-data", value_name = "STRING")]
    pub associated_data: Option<String>,

    #[structopt(short = "f", long = "force", group = "sender")]
    pub force: bool,

    #[structopt(long = "profile", value_name = "PATH", parse(from_os_str))]
    pub profile: Option<PathBuf>
}

fn arg_group(name: &'static str) -> ArgGroup<'static> {
    ArgGroup::with_name(name).required(true)
}
