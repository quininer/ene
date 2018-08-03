use std::path::Path;
use std::str::FromStr;
use std::fs::{ self, File };
use rand::{ Rng, OsRng };
use failure::{ Fallible, err_msg };
use argon2rs::{ Argon2, Variant };
use serde_bytes::ByteBuf;
use serde_cbor as cbor;
use directories::ProjectDirs;
use seckey::{ SecKey, free };
use crate::core::{ alg, key, Builder, Ene };
use crate::core::format::{ PrivateKey, PublicKey, Envelope };
use crate::opts::Profile;
use crate::common::{ Stdio, askpass };


impl Profile {
    pub fn exec(self, dir: &ProjectDirs, quiet: bool, stdio: &mut Stdio) -> Fallible<()> {
        let mut sk_path = dir.data_local_dir().join("key.ene");

        if self.init {
            if let Some(path) = self.profile {
                sk_path = path;
            }

            check!(is_file sk_path);

            init(
                quiet, stdio,
                &self.id.unwrap(),
                self.choose_pubkey.as_ref().map(String::as_str),
                self.choose_encrypt.unwrap_or(alg::Encrypt::Aes128Colm0),
                &sk_path
            )?;
        } else if let Some(path) = self.import {
            check!(is_file sk_path);
            fs::copy(path, sk_path)?;

            if !quiet {
                stdio.info(format_args!("import successfully!"))?;
            }
        } else if let Some(mut path) = self.export_pubkey {
            if let Some(path) = self.profile {
                sk_path = path;
            }

            let sk_packed: PrivateKey = cbor::from_reader(&mut File::open(&sk_path)?)?;
            let sk = askpass(|pass| open(pass.as_bytes(), &sk_packed))?;
            let sk = sk.read();
            let (id, ..) = unwrap!(&sk_packed);

            if path.is_dir() {
                path = path.join(format!("{}.ene", id));
            }

            let pk = sk.as_secret().to_public();
            let pk_packed: PublicKey = Envelope::from((id.to_owned(), pk));
            cbor::to_writer(&mut File::create(&path)?, &pk_packed)?;

            if !quiet {
                stdio.info(format_args!(
                    "PublicKey has been exported to {}",
                    path.canonicalize()?.display()
                ))?;
            }
        } else if let Some(mut path) = self.export_privkey {
            if path.is_dir() {
                let sk_packed: PrivateKey = cbor::from_reader(&mut File::open(&sk_path)?)?;
                let (id, ..) = unwrap!(&sk_packed);

                path = path.join(format!("{}.ene", id));
            }

            check!(is_file path);
            fs::copy(sk_path, &path)?;

            if !quiet {
                stdio.info(format_args!(
                    "PrivateKey has been exported to {}",
                    path.canonicalize()?.display()
                ))?;
            }
        } else {
            unreachable!()
        }

        Ok(())
    }
}

pub fn init(
    quiet: bool,
    stdio: &mut Stdio,
    id: &str,
    algorithms: Option<&str>, enc: alg::Encrypt,
    output: &Path
) -> Fallible<()> {
    let builder = if let Some(algorithms) = algorithms {
        Builder::from_str(algorithms)?
    } else {
        Builder::default()
    };

    let mut rng = OsRng::new()?;
    let ene = SecKey::new(builder.generate(id, &mut rng))
        .map_err(|_| err_msg("Secure alloc fail"))?;
    let ene = ene.read();
    let sk_packed = askpass(|pass| seal(&mut rng, enc, id, pass.as_bytes(), ene.as_secret()))?;

    if !quiet {
        stdio.info(format_args!(
            "Profile successfully initialized\n\nuid: {}\npub: {:#?}",
            ene.get_id(), ene.as_secret().to_public().to_short()
        ))?;
    }

    let mut sk_file = File::create(output)?;
    cbor::to_writer(&mut sk_file, &sk_packed)?;
    sk_file.sync_all()?;

    Ok(())
}

pub fn seal(rng: &mut OsRng, enc: alg::Encrypt, id: &str, key: &[u8], sk: &key::SecretKey) -> Fallible<PrivateKey> {
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

pub fn open(key: &[u8], sk_packed: &PrivateKey) -> Fallible<SecKey<Ene>> {
    let (id, enc, salt, c) = unwrap!(sk_packed);
    let aead = enc.take();

    let mut tmpkey = vec![0; aead.key_length() + aead.nonce_length()];
    Argon2::default(Variant::Argon2d)
        .hash(&mut tmpkey, key, &salt, &[], &[]);
    let (aekey, nonce) = tmpkey.split_at(aead.key_length());

    let mut sk_encoded = vec![0; c.len() - aead.tag_length()];
    aead.open(aekey, nonce, salt, c, &mut sk_encoded)?;

    let sk = cbor::from_slice(&sk_encoded)?;
    let sk = Ene::from(id, sk);
    SecKey::new(sk).map_err(|ene| {
        free(ene);
        err_msg("Secure alloc fail")
    })
}
