use std::path::PathBuf;
use structopt::clap::ArgGroup;
use crate::core::alg::{ self, Protocol };


#[derive(Debug, StructOpt)]
#[structopt(name = "ene")]
#[structopt(raw(long_about = "about()"))]
pub struct Options {
    #[structopt(subcommand)]
    pub subcommand: SubCommand,

    /// Controls when to use color
    #[structopt(
        short = "c", long = "color", value_name = "MODE",
        raw(possible_values = "&ColorChoice::variants()"), default_value = "Auto"
    )]
    pub color: ColorChoice,

    /// Try to be as quiet as possible
    #[structopt(short = "q", long = "quiet")]
    pub quiet: bool
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
    /// Manage profile
    #[structopt(
        name = "profile", display_order = 1,
        raw(group = "arg_group(\"operate\")")
    )]
    Profile(Profile),

    /// Manage contact
    #[structopt(
        name = "contact", display_order = 2,
        raw(group = "arg_group(\"contact\")")
    )]
    Contact(Contact),

    /// Encrypt message
    #[structopt(
        name = "sendto", display_order = 3,
        raw(group = "arg_group(\"recipient\")")
    )]
    SendTo(SendTo),

    /// Decrypt message
    #[structopt(
        name = "recvfrom", display_order = 4,
        raw(group = "arg_group(\"sender\")")
    )]
    RecvFrom(RecvFrom)
}

#[derive(Debug, StructOpt)]
pub struct Profile {
    /// Initialize a Profile
    #[structopt(
        long = "init",
        group = "operate", requires = "id",
        display_order = 1
    )]
    pub init: bool,

    /// The ID of Profile
    #[structopt(name = "id", value_name = "ID")]
    pub id: Option<String>,

    /// Choose PublicKey algorithm
    #[structopt(short = "a", long = "choose-pubkey", value_name = "STRING")]
    pub choose_pubkey: Option<String>,

    /// Choose the encryption algorithm used to encrypt profile
    #[structopt(
        short = "x", long = "choose-encrypt", value_name = "ENCRYPT",
        raw(possible_values = "alg::Encrypt::names()")
    )]
    pub choose_encrypt: Option<alg::Encrypt>,

    /// Import a Profile
    #[structopt(
        short = "i", long = "import",
        value_name = "PATH", group = "operate",
        parse(from_os_str)
    )]
    pub import: Option<PathBuf>,

    /// Export a Profile
    #[structopt(
        short = "E", long = "export-privkey",
        value_name = "PATH", group = "operate",
        parse(from_os_str)
    )]
    pub export_privkey: Option<PathBuf>,

    /// Export a PublicKey
    #[structopt(
        short = "e", long = "export-pubkey",
        value_name = "PATH", group = "operate",
        parse(from_os_str)
    )]
    pub export_pubkey: Option<PathBuf>,

    /// Profile path
    #[structopt(
        short = "p", long = "profile", value_name = "PATH",
        parse(from_os_str)
    )]
    pub profile: Option<PathBuf>
}

#[derive(Debug, StructOpt)]
pub struct Contact {
    /// List the specified contacts
    #[structopt(short = "l", long = "list", group = "contact")]
    pub list: bool,

    /// Contact ID
    #[structopt(name = "id", value_name = "ID")]
    pub id: Option<String>,

    /// Import a contact
    #[structopt(short = "i", long = "import", parse(from_os_str), group = "contact")]
    pub import: Option<PathBuf>,

    /// Export a contact
    #[structopt(
        short = "e", long = "export",
        requires = "id", group = "contact",
        parse(from_os_str)
    )]
    pub export: Option<PathBuf>,

    /// Delete a contact
    #[structopt(short = "d", long = "delete", requires = "id", group = "contact")]
    pub delete: bool,
}

#[derive(Debug, StructOpt)]
pub struct SendTo {
    /// Contact ID
    #[structopt(name = "id", value_name = "ID", group = "recipient")]
    pub recipient: Option<String>,

    /// Input file
    #[structopt(
        short = "i", long = "input", value_name = "PATH",
        parse(from_os_str)
    )]
    pub input: PathBuf,

    /// Output file
    #[structopt(
        short = "o", long = "output", value_name = "PATH",
        parse(from_os_str)
    )]
    pub output: PathBuf,

    /// Specifies encryption protocol
    #[structopt(
        long = "protocol", value_name = "PROTOCOL",
        raw(default_value = "Protocol::default_name()")
    )]
    pub protocol: Protocol,

    /// Associated Data
    #[structopt(short = "a", long = "associated-data", value_name = "STRING")]
    pub associated_data: Option<String>,

    /// Profile path
    #[structopt(
        short = "p", long = "profile", value_name = "PATH",
        parse(from_os_str)
    )]
    pub profile: Option<PathBuf>,

    /// Contact PublicKey path
    #[structopt(
        short = "t", long = "recipient-pubkey",
        value_name = "PATH", group = "recipient",
        parse(from_os_str)
    )]
    pub recipient_pubkey: Option<PathBuf>
}

#[derive(Debug, StructOpt)]
pub struct RecvFrom {
    /// Contact ID
    #[structopt(name = "id", value_name = "ID", group = "sender")]
    pub sender: Option<String>,

    /// Input file
    #[structopt(
        short = "i", long = "input", value_name = "PATH",
        parse(from_os_str)
    )]
    pub input: PathBuf,

    /// Output file
    #[structopt(
        short = "o", long = "output", value_name = "PATH",
        parse(from_os_str)
    )]
    pub output: Option<PathBuf>,

    /// Associated Data
    #[structopt(short = "a", long = "associated-data", value_name = "STRING")]
    pub associated_data: Option<String>,

    /// Force decrypt
    #[structopt(short = "f", long = "force", group = "sender")]
    pub force: bool,

    /// Profile path
    #[structopt(
        short = "p", long = "profile", value_name = "PATH",
        parse(from_os_str)
    )]
    pub profile: Option<PathBuf>,

    /// Contact PublicKey path
    #[structopt(
        short = "t", long = "sender-pubkey",
        value_name = "PATH", group = "sender",
        parse(from_os_str)
    )]
    pub sender_pubkey: Option<PathBuf>
}

fn arg_group(name: &'static str) -> ArgGroup<'static> {
    ArgGroup::with_name(name).required(true)
}

/// TODO const?
fn about() -> &'static str {
    let about = format!("
Supported algorithms:
* Signature: {}
* KeyExchange: {}
* Encryption: {}
",
        alg::Signature::names().join(", "),
        alg::KeyExchange::names().join(", "),
        alg::Encrypt::names().join(", ")
    );

    Box::leak(about.into_boxed_str())
}
