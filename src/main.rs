#![feature(termination_trait_lib, process_exitcode_placeholder)]

#[macro_use] extern crate failure;
#[macro_use] extern crate structopt_derive;
extern crate structopt;
extern crate argon2rs;
extern crate rand;
extern crate serde_bytes;
extern crate serde_cbor;
extern crate directories;
extern crate ttyaskpass;
extern crate ene_core as core;

#[macro_use] mod common;
pub mod opts;
mod profile;

use std::fs;
use failure::{ Error, err_msg };
use structopt::StructOpt;
use directories::ProjectDirs;
use crate::common::Exit;
use crate::opts::{ Options, Profile };


#[inline]
fn start() -> Result<(), Error> {
    let dir = ProjectDirs::from("", "", "ENE").unwrap();

    if !dir.data_local_dir().is_dir() {
        fs::create_dir_all(dir.data_local_dir())?;
    }

    match Options::from_args() {
        Options::Profile(profile) => {
            let sk_path = dir.data_local_dir().join("ene.key");

            if profile.init {
                check!(is_file sk_path);
                profile.init(&sk_path)?;
            } else if let Some(path) = profile.import {
                check!(is_file sk_path);
                fs::copy(path, sk_path)?;
            } else if let Some(mut path) = profile.export {
                if path.is_dir() {
                    path = path.join("ene.key");
                }

                check!(is_file path);
                fs::copy(sk_path, path)?;
            } else {
                Profile::clap().print_help()?;
                println!();
            }
        },
        Options::Contact => unimplemented!(),
        Options::SendTo => unimplemented!(),
        Options::RecvFrom => unimplemented!()
    }

    Ok(())
}

fn main() -> Exit<Error> {
    Exit(start())
}
