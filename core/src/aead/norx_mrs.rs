use sarkara::aead::{ AeadCipher as _, norx_mrs::NorxMRS as NorxMRS2 };
use sarkara::Error;
use crate::define::AeadCipher;
use crate::error::ProtoError;


pub struct NorxMRS;

impl AeadCipher for NorxMRS {
    fn name(&self) -> &'static str {
        "NorxMRS"
    }

    fn key_length(&self) -> usize { NorxMRS2::KEY_LENGTH }
    fn nonce_length(&self) -> usize { NorxMRS2::NONCE_LENGTH }
    fn tag_length(&self) -> usize { NorxMRS2::TAG_LENGTH }

    fn seal(&self, key: &[u8], nonce: &[u8], aad: &[u8], m: &[u8], c: &mut [u8]) -> Result<(), ProtoError> {
        NorxMRS2::new(key)
            .seal(nonce, aad, m, c)
            .map_err(|err| match err {
                Error::Length => ProtoError::InvalidLength,
                _ => unreachable!()
            })
    }

    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], c: &[u8], m: &mut [u8]) -> Result<(), ProtoError> {
        NorxMRS2::new(key)
            .open(nonce, aad, c, m)
            .map_err(|err| match err {
                Error::Length => ProtoError::InvalidLength,
                Error::VerificationFailed => ProtoError::VerificationFailed("NORX-MRS"),
                _ => unreachable!()
            })
    }
}
