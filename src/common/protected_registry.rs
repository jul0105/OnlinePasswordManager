//! Password registry store and encryption

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::{gen_nonce, open, seal, Key, Nonce};

use super::error_message::ErrorMessage;

/// Password registry encrypted
#[derive(Serialize, Deserialize)]
pub struct ProtectedRegistry {
    protected_entries: Vec<u8>,
    nonce: Nonce,
}

impl ProtectedRegistry {
    /// Generate empty password registry (no content to be encrypted)
    pub fn new() -> Self {
        ProtectedRegistry {
            protected_entries: Vec::new(),
            nonce: gen_nonce(),
        }
    }

    /// Decrypt password registry and return Registry if valid
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

/// Password registry decrypted
#[derive(Debug, PartialEq)]
pub struct Registry {
    pub entries: Vec<PasswordEntry>,
    nonce: Nonce,
}

impl Registry {
    /// Encrypt password registry and return ProtectedRegistry
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_registry() {
        let password = PasswordEntry {
            label: "heig-vd.ch".to_string(),
            username: "julien".to_string(),
            password: "1234".to_string(),
        };
        let password2 = password.clone();

        let registry = Registry {
            entries: vec![password],
            nonce: gen_nonce(),
        };

        // Encrypt and decrypt registry with same key
        let key = Key([0; 32]);
        let protected_registry = registry.encrypt(&key);
        let result = protected_registry.decrypt(&key);

        // Should get same entries before/after
        assert!(result.is_ok());
        let registry2 = result.unwrap();
        assert_eq!(registry, registry2);
        assert_eq!(password2, registry2.entries[0]);

        // Encrypt and decrypt registry with DIFFERENT key
        let key = Key([0; 32]);
        let protected_registry = registry.encrypt(&key);
        let key = Key([1; 32]);
        let result = protected_registry.decrypt(&key);

        // Should fail
        assert!(result.is_err());
        assert_eq!(result, Err(ErrorMessage::DecryptionFailed));
    }

    #[test]
    fn test_new_protected_registry() {
        let protected_registry = ProtectedRegistry::new();

        // Entries should be empty
        assert_eq!(protected_registry.protected_entries.len(), 0);
    }
}
