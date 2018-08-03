extern crate rand;
extern crate serde;
extern crate serde_cbor as cbor;
extern crate ene_core;

mod common;

use rand::{ Rng, thread_rng };
use rand::distributions::Alphanumeric;
use ene_core::Builder;
use ene_core::alg::{ self, Protocol };
use ene_core::format::{ Envelope, Version };
use crate::common::Cbor;


#[test]
fn test_ooake_dhaes128colm0() {
    let mut rng = thread_rng();

    let alice = "alice@core.ene";
    let alice_sk = Builder::default().generate(alice, &mut rng);
    let alice_pk = alice_sk.as_secret().to_public();

    let bob = "bob@core.ene";
    let bob_sk = Builder::default().generate(bob, &mut rng);
    let bob_pk = bob_sk.as_secret().to_public();


    let title = "Alice Send to Bob";
    let msg = rng.sample_iter(&Alphanumeric)
        .take(2014)
        .collect::<String>();
    let proto = Protocol::Ooake(alg::KeyExchange::RistrettoDH, alg::Encrypt::Aes128Colm0);

    let enemsg = alice_sk.and(bob, &bob_pk)
        .sendto::<Cbor>(&proto, title.as_bytes(), msg.as_bytes()).unwrap();

    let Envelope(_, v, (_, proto, enemsg)) = enemsg;
    assert_eq!(v, Version::default());
    let msg2 = bob_sk.and(alice, &alice_pk)
        .recvfrom::<Cbor>(&proto, title.as_bytes(), &enemsg, None).unwrap();

    assert_eq!(msg2, msg.as_bytes());
}

#[test]
fn test_sigae_ed25519dhaes128colm0() {
    let mut rng = thread_rng();

    let alice = "alice@core.ene";
    let alice_sk = Builder::default().generate(alice, &mut rng);
    let alice_pk = alice_sk.as_secret().to_public();

    let bob = "bob@core.ene";
    let bob_sk = Builder::default().generate(bob, &mut rng);
    let bob_pk = bob_sk.as_secret().to_public();


    let title = "Alice Send to Bob";
    let msg = rng.sample_iter(&Alphanumeric)
        .take(2014)
        .collect::<String>();
    let proto = Protocol::Sigae(
        false,
        alg::Signature::Ed25519,
        alg::KeyExchange::RistrettoDH,
        alg::Encrypt::Aes128Colm0
    );

    let enemsg = alice_sk.and(bob, &bob_pk)
        .sendto::<Cbor>(&proto, title.as_bytes(), msg.as_bytes()).unwrap();

    let Envelope(_, v, (_, proto, enemsg)) = enemsg;
    assert_eq!(v, Version::default());
    let msg2 = bob_sk.and(alice, &alice_pk)
        .recvfrom::<Cbor>(&proto, title.as_bytes(), &enemsg, None).unwrap();

    assert_eq!(msg2, msg.as_bytes());
}
