#![feature(nll, termination_trait_lib, process_exitcode_placeholder)]

#[macro_use] extern crate clap;
#[macro_use] extern crate structopt;
extern crate argon2rs;
extern crate rand;
extern crate failure;
extern crate serde;
extern crate serde_bytes;
extern crate serde_cbor;
extern crate directories;
extern crate termcolor;
extern crate sled;
extern crate ttyaskpass;
extern crate ene_core as core;

#[macro_use] mod common;
mod opts;
mod profile;
mod contact;

use std::fs;
use failure::{ Error, err_msg };
use structopt::StructOpt;
use directories::ProjectDirs;
use crate::common::{ Exit, Stdio };
use crate::opts::{ Options, SubCommand };


#[inline]
fn start() -> Result<(), Error> {
    let options = Options::from_args();
    let mut stdio = Stdio::new(options.color.into());

    let dir = ProjectDirs::from("", "", "ENE")
        .ok_or_else(|| err_msg("not found project dir"))?;

    if !dir.data_local_dir().is_dir() {
        fs::create_dir_all(dir.data_local_dir())?;
    }

    match options.subcommand {
        SubCommand::Profile(profile) => profile.exec(&dir, &mut stdio)?,
        SubCommand::Contact(contact) => contact.exec(&dir, &mut stdio)?,
        SubCommand::SendTo(sendto) => sendto.exec(&dir, &mut stdio)?,
        SubCommand::RecvFrom(recvfrom) => recvfrom.exec(&dir, &mut stdio)?
    }

    Ok(())
}

fn main() -> Exit<Error> {
    Exit(start())
}
