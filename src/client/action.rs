//! Client facade

use sodiumoxide::crypto::secretbox::Key;
use strum::{Display, EnumIter, EnumString};

use crate::common::error_message::ErrorMessage;
use crate::common::hash::compute_password_hash;
use crate::common::protected_registry::ProtectedRegistry;
use crate::server::endpoint::authentication;
use crate::server::endpoint::download;

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
    encryption_key: Key,
    session_token: String,
    encrypted_file: ProtectedRegistry,
}

impl Session {
    /// Initialize Session. Authenticate with the server to get session token and get encrypted file.
    /// Derive encryption key from password
    ///
    /// Return Session if successful authentication. ErrorMessage otherwise
    pub fn login(
        email: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<Session, ErrorMessage> {
        let auth = compute_password_hash(email, password); // TODO modify this function
        let session_token = authentication(email, &auth.master_password_hash, totp_code)?;
        let encrypted_file = download(&session_token)?;
        Ok(Session {
            session_token,
            encrypted_file,
            encryption_key: Key::from_slice(&auth.master_key).unwrap(),
        })
    }

    /// Get list of passwords labels
    pub fn get_labels(&self) -> Result<Vec<String>, ErrorMessage> {
        todo!();
    }

    /// Get full password's infos for the given password id
    ///
    /// Return Password struct if valid id. ErrorMessage otherwise
    pub fn read_password(&self, password_id: u32) -> Result<String, ErrorMessage> {
        todo!();
    }

    /// Add a new password to the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be added. Ok(()) otherwise
    pub fn add_password(
        &self,
        label: &str,
        username: &str,
        password: &str,
    ) -> Result<(), ErrorMessage> {
        todo!();
    }

    /// Modify given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be modified. Ok(()) otherwise
    pub fn modify_password(
        &self,
        password_id: u32,
        label: &str,
        username: &str,
        password: &str,
    ) -> Result<(), ErrorMessage> {
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
