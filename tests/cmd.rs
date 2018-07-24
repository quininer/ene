extern crate rand;
extern crate failure;
extern crate assert_fs;
extern crate assert_cmd;

use std::{ fs, env };
use std::process::Command;
use rand::{ Rng, thread_rng, distributions::Alphanumeric };
use failure::Error;
use assert_fs::TempDir;
use assert_cmd::prelude::*;


#[test]
fn test_cmd() -> Result<(), Error> {
    Command::cargo_example("dummy_askpass")?
        .assert()
        .success()
        .stdout("password");

    env::set_var("ENE_ASKPASS", "./target/debug/examples/dummy_askpass");

    let tempdir = TempDir::new()?;

    // bob generate privkey
    Command::main_binary()?
        .arg("profile")
        .arg("bob@core.ene").arg("--init")
        .arg("--profile").arg(tempdir.path().join("bob.ene"))
        .assert()
        .success();

    // bob export pubkey
    Command::main_binary()?
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
    Command::main_binary()?
        .arg("sendto")
        .arg("--profile").arg(tempdir.path().join("bob.ene"))
        .arg("--recipient-pubkey").arg("./tests/alice.pk.ene")
        .arg("--associated-data").arg(title)
        .arg("--input").arg(tempdir.path().join("plaintext.txt"))
        .arg("--output").arg(tempdir.path().join("ciphertext.msg.ene"))
        .assert()
        .success();

    // alice recvfrom bob
    let assert = Command::main_binary()?
        .arg("recvfrom")
        .arg("--profile").arg("./tests/alice.ene")
        .arg("--sender-pubkey").arg(tempdir.path().join("bob.pk.ene"))
        .arg("--associated-data").arg(title)
        .arg("--input").arg(tempdir.path().join("ciphertext.msg.ene"))
        .assert()
        .success();

    assert_eq!(assert.get_output().stdout, msg.as_bytes());

    Ok(())
}
