// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Hashing related functions

use argon2::{password_hash::SaltString, Argon2, Params, PasswordHasher};
use base64::encode;
use sha3::{Digest, Sha3_256};
use sodiumoxide::crypto::aead::Key;

#[derive(Debug, Eq, PartialEq)]
pub struct MasterAuth {
    /// Useful key to encrypt or decrypt data  
    /// **Warning**: never transmit it to the server
    pub encryption_key: Key,

    /// Used for authentication to the server
    pub server_auth_password: String,
}

/// Generate key material for the client
///
/// The protected registry's encryption key is derived from the password using Argon2id and email as hash
/// Since the client has to authenticate with the server using a password, the encryption key is re-hashed
/// to get the "server_auth_password" that will be used as a password with the server
///
/// In summary:
/// password --(hashing)--> encryption_key --(hashing)--> server_auth_password
/// The server will receive server_auth_password but cannot derive encryption_key
///
/// Return encryption_key and server_auth_password
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
        encryption_key: Key::from_slice(&master_key).unwrap(),
        server_auth_password: master_password_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_password_hash() {
        let master_auth1 = compute_password_hash("julien@heig-vd.ch", "123456789");
        assert_eq!(master_auth1.encryption_key.0.len(), 32);

        // Equal if same parameters
        let master_auth2 = compute_password_hash("julien@heig-vd.ch", "123456789");
        assert_eq!(master_auth1, master_auth2);

        // Not equal if different email
        let master_auth3 = compute_password_hash("ju@he.ch", "123456789");
        assert_ne!(master_auth1, master_auth3);

        // Not equal if different password
        let master_auth4 = compute_password_hash("julien@heig-vd.ch", "abcd");
        assert_ne!(master_auth1, master_auth4);
    }
}