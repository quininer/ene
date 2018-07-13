#[macro_use] extern crate failure;
#[macro_use] extern crate structopt_derive;
extern crate structopt;
extern crate directories;
extern crate ene_core as core;

mod opts;
mod error;
mod keygen;

use std::io;
use structopt::StructOpt;
use directories::ProjectDirs;
use crate::opts::Options;


fn main() -> io::Result<()> {
    let dir = ProjectDirs::from("", "", "ENE").unwrap();

    match Options::from_args() {
        Options::KeyGen { id, algorithm, output } => {
            //
        },
        Options::SendTo => unimplemented!(),
        Options::RecvFrom => unimplemented!(),
        Options::Contact => unimplemented!()
    }

    Ok(())
}
