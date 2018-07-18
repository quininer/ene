use std::path::Path;
use std::fs::{ self, File };
use failure::{ Error, err_msg };
use serde_cbor as cbor;
use directories::ProjectDirs;
use crate::opts::SendTo;
use crate::profile::open;
use crate::common::{ Cbor, askpass };
use super::db::Db;


impl SendTo {
    pub fn exec(self, dir: &ProjectDirs) -> Result<(), Error> {
        let SendTo { target, input, output, protocol, associated_data } = self;

        let db_path = dir.data_local_dir().join("sled");
        let sk_path = dir.data_local_dir().join("ene.key");

        let db = Db::new(&db_path)?;
        let pk = db.get(&target)?
            .ok_or_else(|| err_msg("not found"))?;

        let sk_packed = cbor::from_reader(&mut File::open(&sk_path)?)?;
        let sk = askpass("Password:", |pass|
            open(pass.as_bytes(), &sk_packed)
        )?;

        let aad = associated_data.unwrap_or_default();
        let message = fs::read(&input)?;

        let encrypted_message = sk.and(&target, &pk)
            .sendto::<Cbor>(&protocol, aad.as_bytes(), &message)?;

        let output = output.unwrap_or_else(|| {
            let ext = Path::new(input.extension().unwrap_or_default()).with_extension("ene");
            input.with_extension(ext)
        });

        cbor::to_writer(&mut File::create(output)?, &encrypted_message)?;

        Ok(())
    }
}
