use rand::prelude::*;

#[allow(dead_code)]
pub fn get_salt_256() -> [u32; 8] {
    let mut rng = rand::rng();

    let mut salt: [u32; 8] = [0; 8];
    for i in 0..8 {
        salt[i] = rng.random::<u32>();
    }

    salt
}