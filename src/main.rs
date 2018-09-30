#![feature(nll, termination_trait_lib, process_exitcode_placeholder)]

#[macro_use] mod common;
mod opts;
mod profile;
mod contact;

use std::fs;
use failure::{ Fallible, Error, err_msg };
use structopt::StructOpt;
use directories::ProjectDirs;
use ene_core as core;
use crate::common::{ Exit, Stdio };
use crate::opts::{ Options, SubCommand };


#[inline]
fn start(quiet: bool, subcommand: SubCommand, stdio: &mut Stdio) -> Fallible<()> {
    let dir = ProjectDirs::from("", "", "ENE")
        .ok_or_else(|| err_msg("not found project dir"))?;

    if !dir.data_local_dir().is_dir() {
        fs::create_dir_all(dir.data_local_dir())?;
    }

    match subcommand {
        SubCommand::Profile(profile) => profile.exec(&dir, quiet, stdio)?,
        SubCommand::Contact(contact) => contact.exec(&dir, quiet, stdio)?,
        SubCommand::SendTo(sendto) => sendto.exec(&dir, quiet, stdio)?,
        SubCommand::RecvFrom(recvfrom) => recvfrom.exec(&dir, quiet, stdio)?
    }

    Ok(())
}

fn main() -> Exit<Error> {
    let options = Options::from_args();
    let mut stdio = Stdio::new(options.color.into());
    let result = start(options.quiet, options.subcommand, &mut stdio);
    Exit(result, stdio)
}
