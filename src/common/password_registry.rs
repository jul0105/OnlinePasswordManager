use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::aead::{gen_nonce, gen_key, open, seal, Key, Nonce};

use super::error_message::ErrorMessage;
use hkdf::Hkdf;
use sha3::Sha3_256;

type HkdfSha256 = Hkdf<Sha3_256>;
const KEY_SIZE: usize = 32;
const STR_INTERNAL_ENCRYPTION_KEY: &[u8; 21] = b"InternalEncryptionKey";
const STR_EXTERNAL_ENCRYPTION_KEY: &[u8; 21] = b"ExternalEncryptionKey";
const STR_INDIVIDUAL_PASSWORD_KEY: &[u8; 21] = b"IndividualPasswordKey";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProtectedEnvelope {
    encrypted_password_registry: EncryptedPasswordRegistry,
    encrypted_master_key: EncryptedMasterKey,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct EncryptedMasterKey {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct EncryptedPasswordRegistry {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OpenedEnvelope {
    encrypted_master_key: EncryptedMasterKey,
    external_encryption_key: Key,
    pub internal_encryption_key: Key,
    pub registry: IndexablePasswordRegistry,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IndexablePasswordRegistry {
    pub entries: Vec<ProtectedPasswordEntry>,
    nonce: Nonce,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProtectedPasswordEntry {
    pub label: String,
    pub username: String,
    encrypted_password: EncryptedPassword,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PasswordEntry {
    pub label: String,
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedPassword {
    ciphertext: Vec<u8>,
    nonce: Nonce,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Password {
    pub password: String,
    nonce: Nonce,
}



impl EncryptedMasterKey {
    fn decrypt(&self, export_key: &Key) -> Result<Key, ErrorMessage> {
        match open(&self.ciphertext, None, &self.nonce, export_key) {
            Ok(plaintext) => match Key::from_slice(&plaintext) {
                Some(master_key) => Ok(master_key),
                None => Err(ErrorMessage::DecryptionFailed),
            },
            Err(_) => Err(ErrorMessage::DecryptionFailed),
        }
    }
}

impl EncryptedPasswordRegistry {
    fn decrypt(&self, internal_encryption_key: &Key) -> Result<IndexablePasswordRegistry, ErrorMessage> {
        match open(&self.ciphertext, None, &self.nonce, internal_encryption_key) {
            Ok(plaintext) => match bincode::deserialize(&plaintext) {
                Ok(passwords) => Ok(IndexablePasswordRegistry {
                    entries: passwords,
                    nonce: self.nonce,
                }),
                Err(_) => Err(ErrorMessage::DeserializeError),
            },
            Err(_) => Err(ErrorMessage::DecryptionFailed),
        }
    }
}

impl IndexablePasswordRegistry {
    fn encrypt(&self, internal_encryption_key: &Key) -> EncryptedPasswordRegistry {
        EncryptedPasswordRegistry {
            nonce: self.nonce,
            ciphertext: seal(
                &bincode::serialize(&self.entries).unwrap(),
                None,
                &self.nonce,
                internal_encryption_key,
            ),
        }
    }
}

impl EncryptedPassword {
    fn decrypt(&self, individual_password_key: &Key) -> Result<Password, ErrorMessage> {
        match open(&self.ciphertext, None, &self.nonce, individual_password_key) {
            Ok(plaintext) => match bincode::deserialize(&plaintext) {
                Ok(password) => Ok(Password {
                    password,
                    nonce: self.nonce,
                }),
                Err(_) => Err(ErrorMessage::DeserializeError),
            },
            Err(_) => Err(ErrorMessage::DecryptionFailed),
        }
    }
}
impl Password {
    fn encrypt(&self, individual_password_key: &Key) -> EncryptedPassword {
        EncryptedPassword {
            nonce: self.nonce,
            ciphertext: seal(
                &bincode::serialize(&self.password).unwrap(),
                None,
                &self.nonce,
                individual_password_key,
            ),
        }
    }
}



impl ProtectedEnvelope {
    /// Generate empty protected envelope (server)
    pub fn new() -> ProtectedEnvelope {
        ProtectedEnvelope {
            encrypted_password_registry: EncryptedPasswordRegistry {
                ciphertext: Vec::new(),
                nonce: gen_nonce(),
            },
            encrypted_master_key: EncryptedMasterKey {
                ciphertext: Vec::new(),
                nonce: gen_nonce(),
            }
        }
    }

    /// Return true if the protected envelope is empty. This means that it has never been initialized by the client
    pub fn is_empty(&self) -> bool {
        self.encrypted_master_key.ciphertext.is_empty()
    }

    /// Initialize protected envelope if empty (client). Generate master key.
    pub fn initialize(&mut self, export_key: &Key) {
        // If empty, generate master key (client)
        if self.is_empty() {
            let master_key = gen_key();
            let nonce = gen_nonce();

            self.encrypted_master_key.ciphertext = seal(master_key.as_ref(), None, &nonce, &export_key);
            self.encrypted_master_key.nonce = nonce;
        }
    }

    /// Open protected envelope by decrypting master key, deriving internal and external encryption key and decrypting password registry.
    /// Provide Opened envelope
    pub fn open(&self, export_key: &Key) -> Result<OpenedEnvelope, ErrorMessage> {
        // Decrypt master key
        let master_key = self.encrypted_master_key.decrypt(export_key)?;

        // Derive internal and external encryption key
        let mut iek = vec![0u8; KEY_SIZE];
        let mut eek = vec![0u8; KEY_SIZE];

        let hk = HkdfSha256::new(None, master_key.as_ref());
        hk.expand(STR_INTERNAL_ENCRYPTION_KEY, &mut iek);
        hk.expand(STR_EXTERNAL_ENCRYPTION_KEY, &mut eek);

        let internal_encryption_key = Key::from_slice(&iek).unwrap();
        let external_encryption_key = Key::from_slice(&eek).unwrap();

        // Decrypt password registry with external encryption key

        let registry = match self.encrypted_password_registry.ciphertext.is_empty() {
            true => {
                IndexablePasswordRegistry {
                    entries: Vec::new(),
                    nonce: self.encrypted_password_registry.nonce
                }
            },
            false => self.encrypted_password_registry.decrypt(&external_encryption_key)?,
        };

        Ok(OpenedEnvelope {
            encrypted_master_key: self.encrypted_master_key.clone(),
            external_encryption_key,
            internal_encryption_key,
            registry,
        })
    }
}

impl OpenedEnvelope {
    /// Encrypt password registry with external encryption key
    pub fn seal(&self) -> ProtectedEnvelope {
        ProtectedEnvelope {
            encrypted_password_registry: self.registry.encrypt(&self.external_encryption_key),
            encrypted_master_key: self.encrypted_master_key.clone(),
        }
    }
}

/// Derive individual password key from internal encryption key and labels
fn derive_individual_password_key(label: &str, username: &str, internal_encryption_key: &Key) -> Key {
    let mut hkdf_label: Vec<u8> = Vec::new();
    hkdf_label.extend_from_slice(STR_INDIVIDUAL_PASSWORD_KEY);
    hkdf_label.extend_from_slice(label.as_ref());
    hkdf_label.extend_from_slice(username.as_ref());

    let mut ipk = vec![0u8; KEY_SIZE];

    let hk = HkdfSha256::new(None, internal_encryption_key.as_ref());
    hk.expand(&hkdf_label, &mut ipk);
    Key::from_slice(&ipk).unwrap()
}

impl PasswordEntry {
    /// Create new password entry and encrypt password
    pub fn seal(&self, internal_encryption_key: &Key) -> ProtectedPasswordEntry {
        // Derive individual password key from internal encryption key and labels
        let individual_password_key = derive_individual_password_key(&self.label, &self.username, internal_encryption_key);

        // Encrypt password with individual password key
        let password_struct = Password {
            password: self.password.clone(),
            nonce: gen_nonce(),
        };

        ProtectedPasswordEntry {
            label: self.label.clone(),
            username: self.username.clone(),
            encrypted_password: password_struct.encrypt(&individual_password_key)
        }
    }
}

impl ProtectedPasswordEntry {
    /// Read a password entry's password
    pub fn open(&self, internal_encryption_key: &Key) -> Result<PasswordEntry, ErrorMessage> {
        // Derive individual password key from internal encryption key and labels
        let individual_password_key = derive_individual_password_key(&self.label, &self.username, internal_encryption_key);

        // Decrypt password with individual password key
        let password = self.encrypted_password.decrypt(&individual_password_key)?;

        Ok(PasswordEntry {
            label: self.label.clone(),
            username: self.username.clone(),
            password: password.password,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_envelope() {
        let export_key = gen_key();

        let mut protected_envelope = ProtectedEnvelope::new();
        protected_envelope.initialize(&export_key);

        let envelope = protected_envelope.open(&export_key);

        println!("{:?}", envelope);
        assert!(envelope.is_ok());

        let en = envelope.unwrap();
        let protected_envelope2 = en.clone().seal();

        // assert_eq!(protected_envelope, protected_envelope2)

        let envelope2 = protected_envelope2.open(&export_key);

        println!("{:?}", envelope2);
        assert!(envelope2.is_ok());
        assert_eq!(en, envelope2.unwrap());
    }

    #[test]
    fn test_encrypt_decrypt_envelope_with_wrong_key() {
        let export_key1 = gen_key();
        let export_key2 = gen_key();
        assert_ne!(export_key1, export_key2);

        let mut protected_envelope = ProtectedEnvelope::new();
        protected_envelope.initialize(&export_key1);

        let envelope = protected_envelope.open(&export_key1);

        println!("{:?}", envelope);
        assert!(envelope.is_ok());

        let en = envelope.unwrap();
        let protected_envelope2 = en.clone().seal();

        // assert_eq!(protected_envelope, protected_envelope2)

        let envelope2 = protected_envelope2.open(&export_key2);

        println!("{:?}", envelope2);
        assert!(envelope2.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_password() {
        let label = "label";
        let username = "username";
        let password = "password";
        let key = gen_key();

        let password_entry = PasswordEntry {
            label: String::from(label),
            username: String::from(username),
            password: String::from(password),
        };

        let protected_password_entry = password_entry.seal(&key);

        assert_eq!(password_entry.label, protected_password_entry.label);
        assert_eq!(password_entry.username, protected_password_entry.username);
        assert_ne!(password_entry.password.as_bytes(), protected_password_entry.encrypted_password.ciphertext);

        let password_entry2 = protected_password_entry.open(&key);

        assert!(password_entry2.is_ok());
        assert_eq!(password_entry, password_entry2.unwrap());
    }

    #[test]
    fn test_encrypt_decrypt_password_with_wrong_key() {
        let label = "label";
        let username = "username";
        let password = "password";
        let key1 = gen_key();
        let key2 = gen_key();
        assert_ne!(key1, key2);

        let password_entry = PasswordEntry {
            label: String::from(label),
            username: String::from(username),
            password: String::from(password),
        };

        let protected_password_entry = password_entry.seal(&key1);

        assert_eq!(password_entry.label, protected_password_entry.label);
        assert_eq!(password_entry.username, protected_password_entry.username);
        assert_ne!(password_entry.password.as_bytes(), protected_password_entry.encrypted_password.ciphertext);

        let password_entry2 = protected_password_entry.open(&key2);

        assert!(password_entry2.is_err());
    }
}