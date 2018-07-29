pub mod db;
mod sendto;
mod recvfrom;

use std::fs::File;
use failure::{ Error, err_msg };
use directories::ProjectDirs;
use serde_cbor as cbor;
use crate::core::format::{ PublicKey, Envelope };
use crate::common::Stdio;
use crate::opts::Contact;
use self::db::Db;


impl Contact {
    pub fn exec(self, dir: &ProjectDirs, quiet: bool, stdio: &mut Stdio) -> Result<(), Error> {
        let db_path = dir.data_local_dir().join("sled");
        let db = Db::new(&db_path)?;

        if self.list {
            let id = self.id.unwrap_or_default();
            let mut started = false;

            for item in db.filter(&id) {
                let (id, pk) = match item {
                    Ok(item) => item,
                    Err(err) => {
                        stdio.warn(format_args!("{:?}", err))?;
                        continue
                    }
                };

                if quiet {
                    stdio.info(format_args!("{}: {:?}", id, pk.to_short()))?;
                } else {
                    if started {
                        stdio.info(format_args!(""))?;
                    }

                    stdio.info(format_args!("uid: {}\npub: {:#?}", id, pk.to_short()))?;
                    started = true;
                }
            }
        } else if let Some(path) = self.import {
            let pk: PublicKey = cbor::from_reader(&mut File::open(path)?)?;
            let (id, pk) = unwrap!(&pk);

            db.set(&id, &pk)?;

            if !quiet {
                stdio.info(format_args!("{} has been imported!", id))?;
            }
        } else if let Some(path) = self.export {
            let id = self.id.unwrap();

            let pk = db.get(&id)?
                .ok_or_else(|| err_msg("ID does not exist."))?;
            let pk_encoded: PublicKey = Envelope::from((id.to_string(), pk));

            cbor::to_writer(&mut File::create(&path)?, &pk_encoded)?;

            if !quiet {
                stdio.info(format_args!("{} has been exported to {}!", id, path.canonicalize()?.display()))?;
            }
        } else if self.delete {
            let id = self.id.unwrap();

            db.del(&id)?;

            if !quiet {
                stdio.info(format_args!("{} has been deleted!", id))?;
            }
        } else {
            unreachable!()
        }

        Ok(())
    }
}
