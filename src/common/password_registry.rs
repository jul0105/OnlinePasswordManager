use std::fmt::Display;

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::{gen_nonce, open, seal, Key, Nonce};

use super::error_message::ErrorMessage;


pub struct ProtectedEnvelope {
    encrypted_password_registry: EncryptedPasswordRegistry,
    encrypted_master_key: EncryptedMasterKey,
}

struct EncryptedMasterKey {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

struct EncryptedPasswordRegistry {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

pub struct OpenedEnvelope {
    external_encryption_key: Key,
    internal_encryption_key: Key,
    pub registry: IndexablePasswordRegistry,
}

pub struct IndexablePasswordRegistry {
    pub passwords: Vec<PasswordEntry>,
    nonce: Nonce,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    encrypted_password: EncryptedPassword,
}

pub struct EncryptedPassword {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

pub struct Password {
    pub password: String,
    nonce: Nonce,
}



impl EncryptedMasterKey {
    fn decrypt(&self) -> Key {}
}
impl EncryptedPasswordRegistry {
    fn decrypt(&self) -> IndexablePasswordRegistry {}
}
impl EncryptedPassword {
    fn decrypt(&self) -> Password {}
}

impl IndexablePasswordRegistry {
    fn encrypt(&self) -> EncryptedPasswordRegistry {}
}
impl Password {
    fn encrypt(&self) -> EncryptedPassword {}
}



impl ProtectedEnvelope {
    pub fn open(&self) -> OpenedEnvelope {
        // Decrypt master key
        // Derive internal and external encryption key
        // Decrypt password registry with external encryption key
    }
}

impl OpenedEnvelope {
    pub fn seal(&self) -> EncryptedPasswordRegistry {
        // Encrypt password registry with external encryption key
    }
}


impl PasswordEntry {
    pub fn new(label: String, username: String, password: String, internal_encryption_key: Key) -> PasswordEntry {
        // Derive individual password key from internal encryption key and labels
        // Encrypt password with individual password key

    }

    pub fn read_password(&self, internal_encryption_key: Key) -> String {
        // Derive individual password key from internal encryption key and labels
        // Decrypt password with individual password key
    }
}