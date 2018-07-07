use generic_array::GenericArray;
use aes::{ Aes128, BlockCipher as _ };
use colm::{ Colm, NONCE_LENGTH };
use colm::traits::{ KEY_LENGTH, BLOCK_LENGTH, BlockCipher };
use crate::define::AeadCipher;
use crate::error;


pub struct Aes128Colm0;

impl AeadCipher for Aes128Colm0 {
    const KEY_LENGTH: usize = KEY_LENGTH;
    const NONCE_LENGTH: usize = NONCE_LENGTH;
    const TAG_LENGTH: usize = BLOCK_LENGTH;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], m: &[u8], c: &mut [u8]) -> error::Result<()> {
        if key.len() != KEY_LENGTH ||
            nonce.len() != NONCE_LENGTH ||
            m.len() + Self::TAG_LENGTH != c.len() ||
            m.is_empty()
        {
            return Err(error::Error::InvalidLength)
        };

        let key = array_ref!(key, 0, KEY_LENGTH);
        let nonce = array_ref!(key, 0, NONCE_LENGTH);

        let cipher: Colm<AesCipher> = Colm::new(key);
        let mut process = cipher.encrypt(nonce, aad);

        let take =
            if m.len() % BLOCK_LENGTH == 0 { (m.len() / BLOCK_LENGTH - 1) * BLOCK_LENGTH }
            else { m.len() / BLOCK_LENGTH * BLOCK_LENGTH };

        let (input, input_remaining) = m.split_at(take);
        let (output, output_remaining) = c.split_at_mut(take);

        for (input, output) in input.chunks(BLOCK_LENGTH)
            .zip(output.chunks_mut(BLOCK_LENGTH))
        {
            let input = array_ref!(input, 0, BLOCK_LENGTH);
            let output = array_mut_ref!(output, 0, BLOCK_LENGTH);
            process.process(input, output);
        }
        process.finalize(input_remaining, output_remaining);

        Ok(())
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], c: &[u8], m: &mut [u8]) -> error::Result<()> {
        if key.len() != KEY_LENGTH ||
            nonce.len() != NONCE_LENGTH ||
            c.len() - Self::TAG_LENGTH != m.len() ||
            m.is_empty()
        {
            return Err(error::Error::InvalidLength)
        };

        let key = array_ref!(key, 0, KEY_LENGTH);
        let nonce = array_ref!(key, 0, NONCE_LENGTH);

        let cipher: Colm<AesCipher> = Colm::new(key);
        let mut process = cipher.decrypt(nonce, aad);

        let take =
            if c.len() % BLOCK_LENGTH == 0 { (c.len() / BLOCK_LENGTH - 2) * BLOCK_LENGTH }
            else { (c.len() / BLOCK_LENGTH - 1) * BLOCK_LENGTH };

        let (input, input_remaining) = c.split_at(take);
        let (output, output_remaining) = m.split_at_mut(take);

        for (input, output) in input.chunks(BLOCK_LENGTH)
            .zip(output.chunks_mut(BLOCK_LENGTH))
        {
            let input = array_ref!(input, 0, BLOCK_LENGTH);
            let output = array_mut_ref!(output, 0, BLOCK_LENGTH);
            process.process(input, output);
        }
        let flag = process.finalize(input_remaining, output_remaining);

        if flag {
            Ok(())
        } else {
            Err(error::Error::VerificationFailed)
        }
    }
}


struct AesCipher(Aes128);

impl BlockCipher for AesCipher {
    const KEY_LENGTH: usize = 16;
    const BLOCK_LENGTH: usize = 16;

    fn new(key: &[u8; KEY_LENGTH]) -> Self {
        AesCipher(Aes128::new(GenericArray::from_slice(key)))
    }

    fn encrypt(&self, block: &mut [u8; BLOCK_LENGTH]) {
        self.0.encrypt_block(GenericArray::from_mut_slice(block));
    }

    fn decrypt(&self, block: &mut [u8; BLOCK_LENGTH]) {
        self.0.decrypt_block(GenericArray::from_mut_slice(block));
    }
}

#[test]
fn test_aead_aes128colm0() {
    use rand::{ Rng, RngCore, thread_rng };

    let mut key = [0; KEY_LENGTH];
    let mut nonce = [0; NONCE_LENGTH];
    let mut aad = vec![0; thread_rng().gen_range(1, 128)];
    let mut m = vec![0; thread_rng().gen_range(1, 256)];
    let mut c = vec![0; m.len() + BLOCK_LENGTH];
    let mut p = vec![0; m.len()];

    thread_rng().fill_bytes(&mut key);
    thread_rng().fill_bytes(&mut nonce);
    thread_rng().fill_bytes(&mut aad);
    thread_rng().fill_bytes(&mut m);

    Aes128Colm0::seal(&key, &nonce, &aad, &m, &mut c).unwrap();
    Aes128Colm0::open(&key, &nonce, &aad, &c, &mut p).unwrap();

    assert_ne!(c, vec![0; m.len()]);
    assert_eq!(p, m);
}
