use std::fs::File;
use std::path::Path;
use rand::{ Rng, OsRng };
use failure::{ Error, err_msg };
use argon2rs::{ Argon2, Variant };
use serde_bytes::ByteBuf;
use serde_cbor as cbor;
use directories::ProjectDirs;
use crate::core::{ alg, key, Builder, Ene };
use crate::core::format::{ PrivateKey, PrivateKeyBorrowed, Envelope };
use crate::core::aead::aes128colm0;
use crate::core::define::AeadCipher;
use crate::opts::Profile;
use crate::common::askpass;


impl Profile {
    pub fn init(&self, output: &Path) -> Result<(), Error> {
        let id = self.id.as_ref().unwrap();
        let enc = self.encrypt.unwrap_or(alg::Encrypt::Aes128Colm0);

        let builder = if let Some(ref algorithm) = self.algorithm {
            let mut builder = Builder::empty();

            for a in algorithm.split(',') {
                match a.trim().to_lowercase().as_str() {
                    "ed25519" => builder.ed25519 = true,
                    "ristrettodh" => builder.ristrettodh = true,
                    a => {
                        warn!("{} algorithm does not support", a);
                    }
                }
            }

            builder
        } else {
            Builder::default()
        };

        let mut rng = OsRng::new()?;
        let ene = builder.generate(id, &mut rng);

        info!("generate private key to {}", output.display());

        let mut sk_file = File::create(output)?;
        let sk_packed = askpass("Password:", |pass|
            seal(&mut rng, enc, id, pass.as_bytes(), ene.as_secret())
        )?;

        cbor::to_writer(&mut sk_file, &sk_packed)?;
        sk_file.sync_all()?;

        Ok(())
    }
}

pub fn seal(rng: &mut OsRng, enc: alg::Encrypt, id: &str, key: &[u8], sk: &key::SecretKey) -> Result<PrivateKey, Error> {
    let aead = match enc {
        alg::Encrypt::Aes128Colm0 => &aes128colm0::Aes128Colm0 as &'static AeadCipher,
        _ => return Err(err_msg("unknown encrypt algorithm"))
    };

    let mut salt = vec![0; 16];
    let mut tmpkey = vec![0; aead.key_length() + aead.nonce_length()];
    rng.fill(salt.as_mut_slice());
    Argon2::default(Variant::Argon2d)
        .hash(&mut tmpkey, key, &salt, &[], &[]);
    let (aekey, nonce) = tmpkey.split_at(aead.key_length());

    let sk_encoded = cbor::to_vec(sk)?;
    let mut output = vec![0; sk_encoded.len() + aead.tag_length()];
    aead.seal(aekey, nonce, &salt, &sk_encoded, &mut output)?;

    Ok(Envelope::from((
        id.to_string(),
        enc,
        ByteBuf::from(salt),
        ByteBuf::from(output)
    )))
}

pub fn open(key: &[u8], sk_packed: &PrivateKeyBorrowed) -> Result<Ene, Error> {
    let Envelope(_, _, (id, enc, salt, c)) = sk_packed;

    let aead = match enc {
        alg::Encrypt::Aes128Colm0 => &aes128colm0::Aes128Colm0 as &'static AeadCipher,
        _ => return Err(err_msg("unknown encrypt algorithm"))
    };

    let mut tmpkey = vec![0; aead.key_length() + aead.nonce_length()];
    Argon2::default(Variant::Argon2d)
        .hash(&mut tmpkey, key, &salt, &[], &[]);
    let (aekey, nonce) = tmpkey.split_at(aead.key_length());

    let mut sk_encoded = vec![0; c.len() - aead.tag_length()];
    aead.open(aekey, nonce, salt, c, &mut sk_encoded)?;

    let sk = cbor::from_slice(&sk_encoded)?;
    Ok(Ene::from(id, sk))
}
