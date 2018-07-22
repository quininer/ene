use std::fs::{ self, File };
use failure::{ Error, err_msg };
use serde_cbor as cbor;
use directories::ProjectDirs;
use crate::core::format::{ PrivateKey, PublicKey };
use crate::{ profile, opts::SendTo };
use crate::common::{ Cbor, Stdio, askpass };
use super::db::Db;


impl SendTo {
    pub fn exec(self, dir: &ProjectDirs, stdio: &mut Stdio) -> Result<(), Error> {
        // take receiver
        let (receiver_id, receiver_pk) = if let Some(ref pk_path) = self.recipient_file {
            let pk_packed: PublicKey = cbor::from_reader(&mut File::open(pk_path)?)?;
            unwrap!(pk_packed)
        } else if let Some(id) = self.recipient {
            let db_path = dir.data_local_dir().join("sled");
            let db = Db::new(&db_path)?;
            let pk = db.get(&id)?
                .ok_or_else(|| err_msg("not found"))?;
            (id, pk)
        } else {
            unreachable!()
        };

        // take sender
        let sk_packed: PrivateKey = if let Some(ref sk_path) = self.profile {
            cbor::from_reader(&mut File::open(sk_path)?)?
        } else {
            let sk_path = dir.data_local_dir().join("ene.key");
            cbor::from_reader(&mut File::open(sk_path)?)?
        };

        let SendTo { input, output, protocol, associated_data, .. } = self;

        // take aad and message
        let aad = associated_data.unwrap_or_default();
        let message = fs::read(&input)?;

        // decrypt sk
        let sk = askpass("Password:", |pass|
            profile::open(pass.as_bytes(), &sk_packed)
        )?;

        // encrypt message
        let message_packed = sk.and(&receiver_id, &receiver_pk)
            .sendto::<Cbor>(&protocol, aad.as_bytes(), &message)?;

        // output
        let output = output.unwrap_or_else(||
            if let Some(ext) = input.extension() {
                let mut ext = ext.to_os_string();
                ext.push(".ene");
                input.with_extension(ext)
            } else {
                input.with_extension("ene")
            }
        );

        cbor::to_writer(&mut File::create(output)?, &message_packed)?;

        Ok(())
    }
}
