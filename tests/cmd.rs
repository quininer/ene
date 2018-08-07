extern crate rand;
extern crate failure;
extern crate escargot;
extern crate assert_fs;
extern crate assert_cmd;

use std::{ fs, env };
use std::process::Command;
use rand::{ Rng, thread_rng, distributions::Alphanumeric };
use failure::Fallible;
use escargot::CargoBuild;
use assert_fs::TempDir;
use assert_cmd::prelude::*;


#[test]
fn test_askpass() -> Fallible<()> {
    Command::cargo_example("dummy_askpass")?
        .assert()
        .success()
        .stdout("password");

    Ok(())
}

#[test]
fn test_cmd() -> Fallible<()> {
    let askpass = CargoBuild::new()
        .example("dummy_askpass")
        .run()?;
    env::set_var("ENE_ASKPASS", askpass.path());

    let tempdir = TempDir::new()?;
    let bin = CargoBuild::new()
        .bin("ene")
        .run()?;

    // bob generate privkey
    bin.command()
        .arg("profile")
        .arg("bob@core.ene").arg("--init")
        .arg("--profile").arg(tempdir.path().join("bob.ene"))
        .assert()
        .success();

    // bob export pubkey
    bin.command()
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
    bin.command()
        .arg("sendto")
        .arg("--profile").arg(tempdir.path().join("bob.ene"))
        .arg("--recipient-pubkey").arg("./tests/common/alice.pk.ene")
        .arg("--associated-data").arg(title)
        .arg("--input").arg(tempdir.path().join("plaintext.txt"))
        .arg("--output").arg(tempdir.path().join("ciphertext.msg.ene"))
        .assert()
        .success();

    // alice recvfrom bob
    let assert = bin.command()
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
    bin.command()
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
    bin.command()
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
