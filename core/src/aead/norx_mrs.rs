use sarkara::aead::{ AeadCipher as _, norx_mrs::NorxMrs as NorxMrs2 };
use sarkara::Error;
use crate::define::AeadCipher;
use crate::error::ProtoError;


pub struct NorxMrs;

impl AeadCipher for NorxMrs {
    fn key_length(&self) -> usize { NorxMrs2::KEY_LENGTH }
    fn nonce_length(&self) -> usize { NorxMrs2::NONCE_LENGTH }
    fn tag_length(&self) -> usize { NorxMrs2::TAG_LENGTH }

    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], m: &[u8], c: &mut [u8]) -> Result<(), ProtoError> {
        NorxMrs2::new(key)
            .seal(nonce, aad, m, c)
            .map_err(|err| match err {
                Error::Length => ProtoError::InvalidLength,
                _ => unreachable!()
            })
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], c: &[u8], m: &mut [u8]) -> Result<(), ProtoError> {
        NorxMrs2::new(key)
            .open(nonce, aad, c, m)
            .map_err(|err| match err {
                Error::Length => ProtoError::InvalidLength,
                Error::VerificationFailed => ProtoError::VerificationFailed("NORX-MRS"),
                _ => unreachable!()
            })
    }
}
