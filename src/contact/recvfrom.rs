use std::io::{ self, Write };
use std::fs::{ self, File };
use failure::{ Error, err_msg };
use serde_cbor as cbor;
use directories::ProjectDirs;
use crate::core::format::{ PrivateKey, Message, Meta };
use crate::{ profile, opts::RecvFrom };
use crate::common::{ Cbor, Stdio, askpass };
use super::db::Db;


impl RecvFrom {
    pub fn exec(self, dir: &ProjectDirs, stdio: &mut Stdio) -> Result<(), Error> {
        // take encrypted message
        let aad = self.associated_data.unwrap_or_default();
        let message_packed: Message = cbor::from_reader(&mut File::open(&self.input)?)?;
        let (meta, proto, message_encrypted) = unwrap!(message_packed);
        let Meta { s: (sender_id, sender_pk), r } = meta;

        // take sender
        let sender_pk = match (self.force, self.sender) {
            (true, _) => sender_pk,
            (_, Some(ref sender)) if sender == &sender_id => {
                let db_path = dir.data_local_dir().join("sled");
                let db = Db::new(&db_path)?;
                let pk = db.get(&sender_id)?
                    .ok_or_else(|| err_msg("not found"))?;

                check!(pk(stdio, "sender pk different: {:?}, {:?}"):
                    pk.ed25519, sender_pk.ed25519;
                    pk.ristrettodh, sender_pk.ristrettodh;
                );

                pk
            },
            (_, Some(ref sender)) => return Err(err_msg(format!("sender id different: {} {}", sender, sender_id))),
            (_, None) => unreachable!()
        };

        // take receiver
        let sk_packed: PrivateKey = if let Some(ref sk_path) = self.profile {
            cbor::from_reader(&mut File::open(sk_path)?)?
        } else {
            let sk_path = dir.data_local_dir().join("ene.key");
            cbor::from_reader(&mut File::open(sk_path)?)?
        };

        // decrypt sk
        let sk = askpass(|pass| profile::open(pass.as_bytes(), &sk_packed))?;

        if let Some((receiver_id, receiver_pk)) = r {
            let (id, ..) = unwrap!(&sk_packed);

            if id != &receiver_id {
                stdio.warn(format_args!("recipient id different: {} {}", id, receiver_id))?;
            }

            let short_pk = sk.as_secret().to_public().to_short();

            check!(pk(stdio, "recipient pk different: {:?}, {:?}"):
                short_pk.ed25519, receiver_pk.ed25519;
                short_pk.ristrettodh, receiver_pk.ristrettodh;
            );
        }

        // decrypt message
        let message = sk.and(&sender_id, &sender_pk)
            .recvfrom::<Cbor>(&proto, aad.as_bytes(), &message_encrypted)?;

        // output
        if let Some(path) = self.output {
            fs::write(path, &message)?
        } else {
            stdio.print(|stdout| stdout.lock().write_all(&message))?;
        }

        Ok(())
    }
}
