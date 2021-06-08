//! Client facade

use strum::{EnumIter, EnumString, Display};

use crate::common::encrypted_file::EncryptedFile;
use crate::common::error_message::ErrorMessage;
use crate::client::password::{PasswordIdentification, Password};

#[derive(Debug, Clone, Copy, Display, EnumIter, EnumString)]
pub enum Action {
    #[strum(to_string = "Read one password")]
    ReadPassword,
    #[strum(to_string = "Add a new password")]
    AddNewPassword,
    #[strum(to_string = "Edit an existing password")]
    EditPassword,
    #[strum(to_string = "Delete an existing password")]
    DeletePassword,
}

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
    pub fn login(username: &str, password: &str, totp_code: &str) -> Result<Session, ErrorMessage> {
        Ok(Session {
            encryption_key: Vec::new(),
            session_token: String::new(),
            encrypted_file: EncryptedFile(String::new()),
        })
    }

    /// Get list of passwords labels
    pub fn get_labels(&self) -> Result<Vec<PasswordIdentification>, ErrorMessage> {
        todo!();
    }

    /// Get full password's infos for the given password id
    ///
    /// Return Password struct if valid id. ErrorMessage otherwise
    pub fn read_password(&self, password_id: u32) -> Result<Password, ErrorMessage> {
        todo!();
    }

    /// Add a new password to the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be added. Ok(()) otherwise
    pub fn add_password(&self, label: &str, username: &str, password: &str) -> Result<(), ErrorMessage> {
        todo!();
    }

    /// Modify given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be modified. Ok(()) otherwise
    pub fn modify_password(&self, password_id: u32, label: &str, username: &str, password: &str) -> Result<(), ErrorMessage> {
        todo!();
    }

    /// Delete given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be deleted. Ok(()) otherwise
    pub fn delete_password(&self, password_id: u32) -> Result<(), ErrorMessage> {
        todo!();
    }
}