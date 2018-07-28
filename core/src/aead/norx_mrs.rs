use sarkara::aead::{ AeadCipher as _, norx_mrs::NorxMrs };
use sarkara::Error;
use crate::define::AeadCipher;
use crate::error::ProtoError;


pub struct NorxMRS;

impl AeadCipher for NorxMRS {
    fn key_length(&self) -> usize { NorxMrs::KEY_LENGTH }
    fn nonce_length(&self) -> usize { NorxMrs::NONCE_LENGTH }
    fn tag_length(&self) -> usize { NorxMrs::TAG_LENGTH }

    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], m: &[u8], c: &mut [u8]) -> Result<(), ProtoError> {
        NorxMrs::new(key)
            .seal(nonce, aad, m, c)
            .map_err(|err| match err {
                Error::Length => ProtoError::InvalidLength,
                _ => unreachable!()
            })
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], c: &[u8], m: &mut [u8]) -> Result<(), ProtoError> {
        NorxMrs::new(key)
            .open(nonce, aad, c, m)
            .map_err(|err| match err {
                Error::Length => ProtoError::InvalidLength,
                Error::VerificationFailed => ProtoError::VerificationFailed("NORX-MRS"),
                _ => unreachable!()
            })
    }
}
