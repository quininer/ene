use std::io::Write;
use std::fs::{ self, File };
use failure::{ Fallible, err_msg };
use serde_cbor as cbor;
use directories::ProjectDirs;
use crate::core::format::{ PrivateKey, PublicKey, Message, Meta };
use crate::{ profile, opts::RecvFrom };
use crate::common::{ Cbor, Stdio, askpass };
use super::db::Db;


impl RecvFrom {
    pub fn exec(self, dir: &ProjectDirs, quiet: bool, stdio: &mut Stdio) -> Fallible<()> {
        // take encrypted message
        let aad = self.associated_data.unwrap_or_default();
        let message_packed: Message = cbor::from_reader(&mut File::open(&self.input)?)?;
        let (meta, proto, message_encrypted) = unwrap!(message_packed);
        let Meta { s: (sender_id, sender_pk), r } = meta;

        // take sender
        let sender_pk = match (self.force, self.sender, self.sender_pubkey) {
            (true, _, _) => sender_pk,
            (_, Some(id), _) => if id == sender_id {
                let db_path = dir.data_local_dir().join("sled");
                let db = Db::new(&db_path)?;
                let pk = db.get(&sender_id)?
                    .ok_or_else(|| err_msg("not found"))?;

                pk.contains(&sender_pk, |name, pk, send_pk|
                    stdio.warn(format_args!("sender {} pk different: {:?}, {:?}", name, pk, send_pk))
                )?;

                pk
            } else {
                return Err(err_msg(format!("sender id different: {} {}", id, sender_id)))
            },
            (_, _, Some(path)) => {
                let pk_packed: PublicKey = cbor::from_reader(&mut File::open(path)?)?;
                let (id, pk) = unwrap!(pk_packed);

                if id == sender_id {
                    pk.contains(&sender_pk, |name, pk, send_pk|
                        stdio.warn(format_args!("sender {} pk different: {:?}, {:?}", name, pk, send_pk))
                    )?;

                    pk
                } else {
                    return Err(err_msg(format!("sender id different: {} {}", id, sender_id)))
                }
            },
            (..) => unreachable!()
        };

        // take receiver
        let sk_packed: PrivateKey = if let Some(ref sk_path) = self.profile {
            cbor::from_reader(&mut File::open(sk_path)?)?
        } else {
            let sk_path = dir.data_local_dir().join("key.ene");
            cbor::from_reader(&mut File::open(sk_path)?)?
        };

        // decrypt sk
        let sk = askpass(|pass| profile::open(pass.as_bytes(), &sk_packed))?;
        let sk = sk.read();

        if let Some((receiver_id, receiver_pk)) = r {
            let (id, ..) = unwrap!(&sk_packed);

            if id != &receiver_id {
                stdio.warn(format_args!("recipient id different: {} {}", id, receiver_id))?;
            }

            let short_pk = sk.as_secret().to_public().to_short();
            short_pk.contains(&receiver_pk, |name, pk, recv_pk|
                stdio.warn(format_args!("recipient {} pk different: {:?}, {:?}", name, pk, recv_pk))
            )?;
        }

        // decrypt message
        let message = sk.and(&sender_id, &sender_pk)
            .recvfrom::<Cbor>(&proto, aad.as_bytes(), &message_encrypted)?;

        if !quiet {
            stdio.info(format_args!("sender: {}", sender_id))?;
            stdio.info(format_args!("recipient: {}", sk.get_id()))?;
            stdio.info(format_args!(""))?;
        }

        // output
        if let Some(path) = self.output {
            fs::write(path, &message)?;
        } else {
            stdio.print(|stdout| stdout.lock().write_all(&message))?;
        }

        Ok(())
    }
}
