#[macro_use] extern crate serde_derive;
extern crate rand;
extern crate failure;
extern crate serde;
extern crate escargot;
extern crate assert_fs;
extern crate assert_cmd;

mod common;

use std::{ fs, env };
use std::process::Command;
use rand::{ Rng, thread_rng, distributions::Alphanumeric };
use failure::Error;
use assert_fs::TempDir;
use assert_cmd::prelude::*;


#[test]
fn test_askpass() -> Result<(), Error> {
    Command::cargo_example("dummy_askpass")?
        .assert()
        .success()
        .stdout("password");

    Ok(())
}

#[test]
fn test_cmd() -> Result<(), Error> {
    let askpass = common::example("dummy_askpass")?;
    env::set_var("ENE_ASKPASS", askpass);

    let tempdir = TempDir::new()?;
    let bin = common::main(&[])?;

    // bob generate privkey
    Command::new(&bin)
        .arg("profile")
        .arg("bob@core.ene").arg("--init")
        .arg("--profile").arg(tempdir.path().join("bob.ene"))
        .assert()
        .success();

    // bob export pubkey
    Command::new(&bin)
        .arg("profile")
        .arg("--profile").arg(tempdir.path().join("bob.ene"))
        .arg("--export-pubkey").arg(tempdir.path().join("bob.pk.ene"))
        .assert()
        .success();

    // write mail
    let title = "Bob to Alice Mail";
    let msg = thread_rng().sample_iter(&Alphanumeric)
        .take(2048)
        .collect::<String>();
    fs::write(tempdir.path().join("plaintext.txt"), &msg)?;

    // bob sendto alice
    Command::new(&bin)
        .arg("sendto")
        .arg("--profile").arg(tempdir.path().join("bob.ene"))
        .arg("--recipient-pubkey").arg("./tests/common/alice.pk.ene")
        .arg("--associated-data").arg(title)
        .arg("--input").arg(tempdir.path().join("plaintext.txt"))
        .arg("--output").arg(tempdir.path().join("ciphertext.msg.ene"))
        .assert()
        .success();

    // alice recvfrom bob
    let assert = Command::new(&bin)
        .arg("-q")
        .arg("recvfrom")
        .arg("--profile").arg("./tests/common/alice.ene")
        .arg("--sender-pubkey").arg(tempdir.path().join("bob.pk.ene"))
        .arg("--associated-data").arg(title)
        .arg("--input").arg(tempdir.path().join("ciphertext.msg.ene"))
        .assert()
        .success();

    assert_eq!(assert.get_output().stdout, msg.as_bytes());


    // sign

    // bob sendto alice
    Command::new(&bin)
        .arg("sendto")
        .arg("--profile").arg(tempdir.path().join("bob.ene"))
        .arg("--recipient-pubkey").arg("./tests/common/alice.pk.ene")
        .arg("--protocol").arg("sonly-ed25519")
        .arg("--associated-data").arg(title)
        .arg("--input").arg(tempdir.path().join("plaintext.txt"))
        .arg("--output").arg(tempdir.path().join("ciphertext.msg.ene"))
        .assert()
        .success();

    // alice recvfrom bob
    Command::new(&bin)
        .arg("-q")
        .arg("recvfrom")
        .arg("--profile").arg("./tests/common/alice.ene")
        .arg("--sender-pubkey").arg(tempdir.path().join("bob.pk.ene"))
        .arg("--associated-data").arg(title)
        .arg("--input").arg(tempdir.path().join("ciphertext.msg.ene"))
        .arg("--plaintext").arg(tempdir.path().join("plaintext.txt"))
        .assert()
        .success();

    Ok(())
}
