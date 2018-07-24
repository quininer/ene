use std::path::Path;
use std::fs::{ self, File };
use rand::{ Rng, OsRng };
use failure::{ Error, err_msg };
use argon2rs::{ Argon2, Variant };
use serde_bytes::ByteBuf;
use serde_cbor as cbor;
use directories::ProjectDirs;
use crate::core::{ alg, key, Builder, Ene };
use crate::core::format::{ PrivateKey, PublicKey, Envelope };
use crate::core::aead::aes128colm0;
use crate::core::define::AeadCipher;
use crate::opts::Profile;
use crate::common::{ Stdio, askpass };


impl Profile {
    pub fn exec(self, dir: &ProjectDirs, stdio: &mut Stdio) -> Result<(), Error> {
        let mut sk_path = dir.data_local_dir().join("ene.key");

        if self.init {
            if let Some(path) = self.profile {
                sk_path = path;
            }

            check!(is_file sk_path);

            init(
                stdio,
                &self.id.unwrap(),
                self.algorithm.as_ref().map(String::as_str),
                self.encrypt.unwrap_or(alg::Encrypt::Aes128Colm0),
                &sk_path
            )?;
        } else if let Some(path) = self.import {
            check!(is_file sk_path);
            fs::copy(path, sk_path)?;
        } else if let Some(mut path) = self.export_pubkey {
            if let Some(path) = self.profile {
                sk_path = path;
            }

            let sk_packed: PrivateKey = cbor::from_reader(&mut File::open(&sk_path)?)?;
            let sk = askpass(|pass| open(pass.as_bytes(), &sk_packed))?;
            let (id, ..) = unwrap!(&sk_packed);

            if path.is_dir() {
                path = path.join(format!("{}.ene", id));
            }

            let pk = sk.as_secret().to_public();
            let pk_packed: PublicKey = Envelope::from((id.to_owned(), pk));
            cbor::to_writer(&mut File::create(&path)?, &pk_packed)?;
        } else if let Some(mut path) = self.export_privkey {
            if path.is_dir() {
                let sk_packed: PrivateKey = cbor::from_reader(&mut File::open(&sk_path)?)?;
                let (id, ..) = unwrap!(&sk_packed);

                path = path.join(format!("{}.ene", id));
            }

            check!(is_file path);
            fs::copy(sk_path, path)?;
        } else {
            unreachable!()
        }

        stdio.info(format_args!("Done!"))?;
        Ok(())
    }
}

pub fn init(
    stdio: &mut Stdio,
    id: &str,
    algorithm: Option<&str>, enc: alg::Encrypt,
    output: &Path
) -> Result<(), Error> {
    let builder = if let Some(algorithm) = algorithm {
        let mut builder = Builder::empty();

        for a in algorithm.split(',') {
            match a.trim().to_lowercase().as_str() {
                "ed25519" => builder.ed25519 = true,
                "ristrettodh" => builder.ristrettodh = true,
                a => {
                    stdio.warn(format_args!("{} algorithm does not support", a))?;
                }
            }
        }

        builder
    } else {
        Builder::default()
    };

    let mut rng = OsRng::new()?;
    let ene = builder.generate(id, &mut rng);
    let sk_packed = askpass(|pass| seal(&mut rng, enc, id, pass.as_bytes(), ene.as_secret()))?;

    let mut sk_file = File::create(output)?;
    cbor::to_writer(&mut sk_file, &sk_packed)?;
    sk_file.sync_all()?;

    Ok(())
}

pub fn seal(rng: &mut OsRng, enc: alg::Encrypt, id: &str, key: &[u8], sk: &key::SecretKey) -> Result<PrivateKey, Error> {
    let aead = enc.take();

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

pub fn open(key: &[u8], sk_packed: &PrivateKey) -> Result<Ene, Error> {
    let (id, enc, salt, c) = unwrap!(sk_packed);
    let aead = enc.take();

    let mut tmpkey = vec![0; aead.key_length() + aead.nonce_length()];
    Argon2::default(Variant::Argon2d)
        .hash(&mut tmpkey, key, &salt, &[], &[]);
    let (aekey, nonce) = tmpkey.split_at(aead.key_length());

    let mut sk_encoded = vec![0; c.len() - aead.tag_length()];
    aead.open(aekey, nonce, salt, c, &mut sk_encoded)?;

    let sk = cbor::from_slice(&sk_encoded)?;
    Ok(Ene::from(id, sk))
}
