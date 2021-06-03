//! Hashing related functions

use argon2::{password_hash::SaltString, Argon2, Params, PasswordHasher};
use base64::encode;
use sha3::{Digest, Sha3_256};

#[derive(Debug)]
pub struct MasterAuth {
    /// Useful key to encrypt or decrypt data  
    /// **Warning**: never transmit it to the server
    pub master_key: Vec<u8>,

    /// Used for authentication to the server
    pub master_password_hash: String,
}

pub fn compute_password_hash(email: &str, password: &str) -> MasterAuth {
    let argon = Argon2::default();
    let email_hash = &encode(Sha3_256::digest(&email.as_bytes()))[..16];
    let salt = SaltString::new(email_hash).unwrap();
    let master_key = argon
        .hash_password(
            password.as_bytes(),
            None,
            Params {
                t_cost: 4,
                m_cost: 8192,
                ..Default::default()
            },
            &salt,
        )
        .unwrap()
        .hash
        .unwrap()
        .as_bytes()
        .to_vec();

    let password_hash = &encode(Sha3_256::digest(&password.as_bytes()))[..16];
    let master_password_salt = SaltString::new(password_hash).unwrap();
    let master_password_hash = argon
        .hash_password_simple(&master_key, &master_password_salt)
        .unwrap()
        .hash
        .unwrap()
        .to_string();

    MasterAuth {
        master_key,
        master_password_hash,
    }
}
