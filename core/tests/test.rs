extern crate rand;
extern crate serde;
extern crate serde_cbor as cbor;
extern crate ene_core;

use rand::{ Rng, thread_rng };
use rand::distributions::Alphanumeric;
use serde::{ Serialize, Deserialize };
use serde_cbor::error::Error as CborError;
use ene_core::{ error, Builder };
use ene_core::alg::{ self, Protocol };
use ene_core::format::{ Envelope, Version };
use ene_core::define::Serde;


pub struct Cbor;

impl Serde for Cbor {
    type Error = CborError;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, error::Error<Self::Error>> {
        cbor::to_vec(value)
            .map_err(|err| error::Error::Format(err.into()))
    }

    fn from_slice<'a, T: Deserialize<'a>>(slice: &'a [u8]) -> Result<T, error::Error<Self::Error>> {
        cbor::from_slice(slice)
            .map_err(|err| error::Error::Format(err.into()))
    }
}


#[test]
fn test_ene() {
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
        .recvfrom::<Cbor>(&proto, title.as_bytes(), &enemsg).unwrap();

    assert_eq!(msg2, msg.as_bytes());
}
