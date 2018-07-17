extern crate failure;
extern crate serde_cbor as cbor;
extern crate ene_core;

use std::str::FromStr;
use failure::Error;
use ene_core::alg;
use ene_core::format::{ Envelope, PK, MSG };


#[test]
fn test_envelope() -> Result<(), Error> {
    let message = "message";
    let m: Envelope<MSG, String> = Envelope::from(message.to_owned());
    let data = cbor::to_vec(&m)?;
    let Envelope(_, _, message2): Envelope<MSG, String> = cbor::from_slice(&data)?;

    assert_eq!(message, message2);

    Ok(())
}


#[should_panic]
#[test]
fn test_badenvelope() {
    let message = "message";
    let m: Envelope<PK, String> = Envelope::from(message.to_owned());
    let data = cbor::to_vec(&m).unwrap();
    let _m: Envelope<MSG, String> =
        cbor::from_slice(&data).unwrap();
}

#[test]
fn test_protocol_parse() {
    assert_eq!(
        alg::Protocol::Ooake(alg::KeyExchange::RistrettoDH, alg::Encrypt::Aes128Colm0),
        alg::Protocol::from_str("ooake-ristrettodh-aes128colm0").unwrap()
    );

    assert!(alg::Protocol::from_str("ooake-ristrettodh").is_err());
    assert!(alg::Protocol::from_str("ooake-kyber-aes128colm0").is_err());
}
