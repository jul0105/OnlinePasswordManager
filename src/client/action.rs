//! Client facade

use crate::common::encrypted_file::EncryptedFile;
use crate::common::error_message::ErrorMessage;
use crate::client::password::{PasswordIdentification, Password};

pub struct Session {
    encryption_key: Vec<u8>, // TODO change to Key type (see sodiumoxide)
    session_token: String,
    encrypted_file: EncryptedFile,
}

impl Session {
    /// Initialize Session. Authenticate with the server to get session token and get encrypted file.
    /// Derive encryption key from password
    ///
    /// Return Session if successful authentication. ErrorMessage otherwise
    fn login(username: &str, password: &str, totp_code: &str) -> Result<Session, ErrorMessage> {
        Err(ErrorMessage::ToImplement) // TODO implement
    }

    /// Get list of passwords labels
    fn get_labels(&self) -> Result<Vec<PasswordIdentification>, ErrorMessage> {
        Err(ErrorMessage::ToImplement) // TODO implement
    }


    /// Get full password's infos for the given password id
    ///
    /// Return Password struct if valid id. ErrorMessage otherwise
    fn read_password(&self, password_id: u32) -> Result<Password, ErrorMessage> {
        Err(ErrorMessage::ToImplement) // TODO implement
    }

    /// Add a new password to the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be added. Ok(()) otherwise
    fn add_password(&self, label: &str, username: &str, password: &str) -> Result<(), ErrorMessage> {
        Err(ErrorMessage::ToImplement) // TODO implement
    }

    /// Modify given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be modified. Ok(()) otherwise
    fn modify_password(&self, password_id: u32, label: &str, username: &str, password: &str) -> Result<(), ErrorMessage> {
        Err(ErrorMessage::ToImplement) // TODO implement
    }

    /// Delete given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be deleted. Ok(()) otherwise
    fn delete_password(&self, password_id: u32) -> Result<(), ErrorMessage> {
        Err(ErrorMessage::ToImplement) // TODO implement
    }
}