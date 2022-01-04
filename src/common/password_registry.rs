use std::fmt::Display;

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::{gen_nonce, open, seal, Key, Nonce};

use super::error_message::ErrorMessage;


pub struct ProtectedEnvelope {
    encrypted_password_registry: EncryptedPasswordRegistry,
    encrypted_master_key: EncryptedMasterKey,
}

pub struct EncryptedMasterKey {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

pub struct EncryptedPasswordRegistry {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

pub struct OpenedEnvelope {
    external_encryption_key: Key,
    internal_encryption_key: Key,
    pub indexable_password_registry: IndexablePasswordRegistry,
}

pub struct IndexablePasswordRegistry {
    pub passwords: Vec<PasswordEntry>,
    nonce: Nonce,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub encrypted_password: EncryptedPassword,
}

pub struct EncryptedPassword {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}
pub struct Password {
    pub password: String,
    nonce: Nonce,
}




impl ProtectedEnvelope {
    pub fn open(&self) -> OpenedEnvelope {}
}

impl OpenedEnvelope {
    pub fn seal(&self) -> EncryptedPasswordRegistry {}
}


impl PasswordEntry {
    pub fn seal(label: String, username: String, password: String, internal_encryption_key: Key) -> PasswordEntry {}

    pub fn open(&self, internal_encryption_key: Key) -> String {}
}