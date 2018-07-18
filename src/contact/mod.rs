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
use crate::opts::Contact;
use self::db::Db;


impl Contact {
    pub fn exec(self, dir: &ProjectDirs) -> Result<(), Error> {
        let db_path = dir.data_local_dir().join("sled");

        if self.list {
            let id = self.id.unwrap_or_default();
            let db = Db::new(&db_path)?;

            for item in db.filter(&id) {
                let (id, pk) = match item {
                    Ok(item) => item,
                    Err(err) => {
                        warn!("{:?}", err);
                        continue
                    }
                };

                println!("{}: {:?}", id, pk.to_short());
            }
        } else if let Some(path) = self.import {
            let Envelope(_, _, (id, pk)): PublicKey = cbor::from_reader(&mut File::open(path)?)?;
            let db = Db::new(&db_path)?;

            db.set(&id, &pk)?;

            println!("import {}", id);
        } else if let Some(path) = self.export {
            let id = self.id.ok_or_else(|| err_msg("need id"))?;
            let db = Db::new(&db_path)?;

            let pk = db.get(&id)?.ok_or_else(|| err_msg("empty"))?;
            let pk_encoded: PublicKey = Envelope::from((id.to_owned(), pk));

            cbor::to_writer(&mut File::create(&path)?, &pk_encoded)?;
        } else if self.delete {
            let id = self.id.ok_or_else(|| err_msg("need id"))?;
            let db = Db::new(&db_path)?;

            db.del(&id)?;
        } else {
            let mut stdout = io::stdout();
            Contact::clap().write_help(&mut stdout)?;
            writeln!(&mut stdout)?;
        }

        Ok(())
    }
}
