#![feature(nll, termination_trait_lib, process_exitcode_placeholder)]

#[macro_use] extern crate structopt;
extern crate argon2rs;
extern crate rand;
extern crate failure;
extern crate serde;
extern crate serde_bytes;
extern crate serde_cbor;
extern crate directories;
extern crate fs2;
extern crate sled;
extern crate ttyaskpass;
extern crate ene_core as core;

#[macro_use] mod common;
mod opts;
mod profile;
mod contact;

use std::fs;
use failure::Error;
use structopt::StructOpt;
use directories::ProjectDirs;
use crate::common::Exit;
use crate::opts::Options;


#[inline]
fn start() -> Result<(), Error> {
    let dir = ProjectDirs::from("", "", "ENE").unwrap();

    if !dir.data_local_dir().is_dir() {
        fs::create_dir_all(dir.data_local_dir())?;
    }

    match Options::from_args() {
        Options::Profile(profile) => profile.exec(&dir)?,
        Options::Contact(contact) => contact.exec(&dir)?,
        Options::SendTo(sendto) => sendto.exec(&dir)?,
        Options::RecvFrom => unimplemented!()
    }

    Ok(())
}

fn main() -> Exit<Error> {
    Exit(start())
}
