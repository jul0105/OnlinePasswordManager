use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::{gen_nonce, open, seal, Key, Nonce};

use super::error_message::ErrorMessage;

pub type ProtectedEntry = Vec<u8>;

#[derive(Serialize, Deserialize)]
pub struct ProtectedRegistry {
    protected_entries: Vec<ProtectedEntry>,
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
        let entries = self
            .protected_entries
            .iter()
            .map(
                |protected_entry| match open(&protected_entry, None, &self.nonce, master_key) {
                    Ok(data) => Ok(bincode::deserialize::<PasswordEntry>(&data).unwrap()),
                    Err(_) => Err(()),
                },
            )
            .collect::<Vec<Result<PasswordEntry, ()>>>();

        if entries.iter().any(|entry| entry.is_err()) {
            return Err(ErrorMessage::PasswordEntryDecryptionFailed);
        } else {
            return Ok(Registry {
                entries: entries.into_iter().map(|entry| entry.unwrap()).collect(),
                nonce: self.nonce,
            });
        }
    }
}

pub struct Registry {
    pub entries: Vec<PasswordEntry>,
    nonce: Nonce,
}

impl Registry {
    pub fn encrypt(&self, master_key: &Key) -> ProtectedRegistry {
        let protected_entries = self
            .entries
            .iter()
            .map(|entry| {
                return seal(
                    &bincode::serialize(entry).unwrap(),
                    None,
                    &self.nonce,
                    master_key,
                );
            })
            .collect::<Vec<ProtectedEntry>>();
        return ProtectedRegistry {
            nonce: self.nonce,
            protected_entries,
        };
    }
}

#[derive(Serialize, Deserialize)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub password: String,
}
