use std::io::{ self, Write };
use std::path::PathBuf;
use std::fs::{ self, File };
use failure::{ Error, err_msg };
use serde_cbor as cbor;
use directories::ProjectDirs;
use crate::core::key::{ SecretKey, PublicKey };
use crate::core::format::{ Message, Meta };
use crate::opts::RecvFrom;
use crate::profile;
use crate::common::{ Cbor, askpass };
use super::db::Db;


impl RecvFrom {
    pub fn exec(self, dir: &ProjectDirs) -> Result<(), Error> {
        // take encrypted message
        let aad = self.associated_data.unwrap_or_default();
        let message_packed: Message = cbor::from_reader(&mut File::open(&self.input)?)?;
        let (meta, proto, message_encrypted) = unwrap!(message_packed);
        let Meta { s: (sender_id, sender_pk), r } = meta;

        // take sender
        let sender_pk = if self.force {
            sender_pk
        } else if self.target == sender_id {
            let db_path = dir.data_local_dir().join("sled");
            let db = Db::new(&db_path)?;
            let pk = db.get(&sender_id)?
                .ok_or_else(|| err_msg("not found"))?;

            // TODO check

            pk
        } else {
            return Err(err_msg("id different"));
        };

        // take receiver
        let sk_packed = if let Some(ref sk_path) = self.profile {
            cbor::from_reader(&mut File::open(sk_path)?)?
        } else {
            let sk_path = dir.data_local_dir().join("ene.key");
            cbor::from_reader(&mut File::open(sk_path)?)?
        };

        // decrypt sk
        let sk = askpass("Password:", |pass|
            profile::open(pass.as_bytes(), &sk_packed)
        )?;

        if let Some((receiver_id, receiver_pk)) = r {
            // TODO check
        }

        // decrypt message
        let message = sk.and(&sender_id, &sender_pk)
            .recvfrom::<Cbor>(&proto, aad.as_bytes(), &message_encrypted)?;

        // output
        if let Some(path) = self.output {
            fs::write(path, &message)?
        } else {
            io::stdout()
                .lock()
                .write_all(&message)?;
        }

        Ok(())
    }
}
