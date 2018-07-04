pub mod ed25519;
pub mod ristretto_dh;


pub struct SecretKey {
    ed25519: ed25519::SecretKey,
    ristretto_dh: ristretto_dh::SecretKey
}

pub struct PublicKey {
    ed25519: ed25519::PublicKey,
    ristretto_dh: ristretto_dh::PublicKey
}
