pub mod db;
mod sendto;
mod recvfrom;

use std::fs::File;
use std::io::{ self, Write };
use failure::{ Error, err_msg };
use structopt::StructOpt;
use directories::ProjectDirs;
use serde_cbor as cbor;
use crate::core::format::{ PublicKey, Envelope };
use crate::common::Stdio;
use crate::opts::Contact;
use self::db::Db;


impl Contact {
    pub fn exec(self, dir: &ProjectDirs, stdio: &mut Stdio) -> Result<(), Error> {
        let db_path = dir.data_local_dir().join("sled");
        let db = Db::new(&db_path)?;

        if self.list {
            let id = self.id.unwrap_or_default();

            for item in db.filter(&id) {
                let (id, pk) = match item {
                    Ok(item) => item,
                    Err(err) => {
                        stdio.warn(format_args!("{:?}", err))?;
                        continue
                    }
                };

                println!("{}: {:?}", id, pk.to_short());
            }
        } else if let Some(path) = self.import {
            let pk: PublicKey = cbor::from_reader(&mut File::open(path)?)?;
            let (id, pk) = unwrap!(&pk);

            db.set(&id, &pk)?;

            println!("import {}", id);
        } else if let Some(path) = self.export {
            let id = self.id.ok_or_else(|| err_msg("need id"))?;

            let pk = db.get(&id)?.ok_or_else(|| err_msg("empty"))?;
            let pk_encoded: PublicKey = Envelope::from((id.to_owned(), pk));

            cbor::to_writer(&mut File::create(&path)?, &pk_encoded)?;
        } else if self.delete {
            let id = self.id.ok_or_else(|| err_msg("need id"))?;

            db.del(&id)?;
        } else {
            unreachable!()
        }

        Ok(())
    }
}
