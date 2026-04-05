use rand::{Rng, rng};

pub fn generate_secret<const N: usize>() -> [u8; N] {
    let mut key = [0u8; N];
    rng().fill_bytes(&mut key);
    key
}
