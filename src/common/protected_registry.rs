use std::fmt::Display;

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::{gen_nonce, open, seal, Key, Nonce};

use super::error_message::ErrorMessage;

#[derive(Serialize, Deserialize)]
pub struct ProtectedRegistry {
    protected_entries: Vec<u8>,
    nonce: Nonce,
}

impl ProtectedRegistry {
    pub fn new() -> Self {
        ProtectedRegistry {
            protected_entries: Vec::new(),
            nonce: gen_nonce(),
        }
    }
    pub fn decrypt(&self, master_key: &Key) -> Result<Registry, ErrorMessage> {
        if self.protected_entries.len() > 0 {
            match open(&self.protected_entries, None, &self.nonce, master_key) {
                Ok(protected_entries) => match bincode::deserialize(&protected_entries) {
                    Ok(entries) => Ok(Registry {
                        entries,
                        nonce: self.nonce,
                    }),
                    Err(_) => Err(ErrorMessage::DeserializeError),
                },
                Err(_) => Err(ErrorMessage::DecryptionFailed),
            }
        } else {
            Ok(Registry {
                nonce: self.nonce,
                entries: Vec::new(),
            })
        }
    }
}

#[derive(Debug)]
pub struct Registry {
    pub entries: Vec<PasswordEntry>,
    nonce: Nonce,
}

impl Registry {
    pub fn encrypt(&self, master_key: &Key) -> ProtectedRegistry {
        ProtectedRegistry {
            nonce: self.nonce,
            protected_entries: seal(
                &bincode::serialize(&self.entries).unwrap(),
                None,
                &self.nonce,
                master_key,
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub password: String,
}

impl Display for PasswordEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Label: {}\nUsername: {}\nPassword: {}",
            self.label, self.username, self.password
        )
    }
}
