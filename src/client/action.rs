// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Client facade

use sodiumoxide::crypto::aead::Key;
use khape::{Client, Parameters};

use crate::client::hash::compute_password_hash;
use crate::common::error_message::ErrorMessage;
use crate::common::protected_registry::{PasswordEntry, Registry};
use crate::server::endpoint::{download, login_khape_start, login_khape_finish, register_khape_finish, register_khape_start};
use crate::server::endpoint::{authentication, upload};

#[derive(Debug)]
pub struct Session {
    master_key: Key,
    session_key: String,
    pub registry: Registry,
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
        let auth = compute_password_hash(email, password);
        // let session_token = authentication(email, &auth.server_auth_password, totp_code)?; // TODO totp
        let session_key = Session::login_khape(email, &auth.server_auth_password).unwrap();
        let session_token = base64::encode(session_key);
        let protected_registry = download(&session_token)?;
        let registry = protected_registry.decrypt(&auth.encryption_key)?;
        Ok(Session {
            session_key: session_token,
            master_key: auth.encryption_key,
            registry,
        })
    }

    fn login_khape(email: &str, password: &str) -> Option<[u8; 32]> {
        let params = Parameters::default();
        let client = Client::new(params, String::from(email));

        let (auth_request, oprf_client_state) = client.auth_start(password.as_ref());
        let auth_response = login_khape_start(auth_request);
        let (auth_verify_request, ke_output) = client.auth_ke(auth_response, oprf_client_state);
        let auth_verify_response = login_khape_finish(auth_verify_request);
        let output_key = client.auth_finish(auth_verify_response, ke_output);

        output_key
    }

    fn register_khape(email: &str, password: &str) {
        let params = Parameters::default();
        let client = Client::new(params, String::from(email));

        let (register_request, oprf_client_state) = client.register_start(password.as_ref());
        let register_response = register_khape_start(register_request);
        let register_finish = client.register_finish(register_response, oprf_client_state);
        register_khape_finish(register_finish);
    }

    /// Add a new password to the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be added. Ok(()) otherwise
    pub fn add_password(
        &mut self,
        label: &str,
        username: &str,
        password: &str,
    ) -> Result<(), ErrorMessage> {
        self.registry.entries.push(PasswordEntry {
            label: label.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
        });
        self.seal_and_send()
    }

    /// Modify given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be modified. Ok(()) otherwise
    pub fn modify_password(
        &mut self,
        password_id: usize,
        label: &str,
        username: &str,
        password: &str,
    ) -> Result<(), ErrorMessage> {
        let entry: &mut PasswordEntry = match self.registry.entries.get_mut(password_id) {
            Some(val) => val,
            None => return Err(ErrorMessage::PasswordEntryNotFound),
        };

        entry.label = String::from(label);
        entry.username = String::from(username);
        entry.password = String::from(password);
        self.seal_and_send()?;
        Ok(())
    }

    /// Delete given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be deleted. Ok(()) otherwise
    pub fn delete_password(&mut self, index: usize) -> Result<(), ErrorMessage> {
        self.registry.entries.remove(index);
        self.seal_and_send()
    }

    /// Encrypt the protected registry and send it to the server
    ///
    /// Return server's error if upload fail or Ok if successful
    fn seal_and_send(&self) -> Result<(), ErrorMessage> {
        let protected_registry = self.registry.encrypt(&self.master_key);
        upload(&self.session_key, protected_registry)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::server::repository::tests::DATABASE;

    #[test]
    fn test_login() {
        let db = DATABASE.lock().unwrap();
        db.add_user(
            "gil@demo.ch",
            &compute_password_hash("gil@demo.ch", "coucou").server_auth_password,
            None,
        )
        .unwrap();
        let session = Session::login("gil@demo.ch", "coucou", None);
        assert!(session.is_ok(), "{:?}", session);
    }

    #[test]
    fn test_login_failed() {
        DATABASE.lock().ok();
        let session = Session::login("albert@demo.ch", "coucou", None);
        assert!(session.is_err(), "{:?}", session);
        assert_eq!(ErrorMessage::AuthFailed, session.unwrap_err());
    }

    #[test]
    fn test_login_failed_totp() {
        let db = DATABASE.lock().unwrap();
        db.add_user(
            "gil1@demo.ch",
            &compute_password_hash("gil1@demo.ch", "coucou").server_auth_password,
            Some("abcd"),
        )
        .unwrap();
        let session = Session::login("gil1@demo.ch", "coucou", None);
        assert!(session.is_err(), "{:?}", session);
        assert_eq!(ErrorMessage::TotpRequired, session.unwrap_err());
    }

    #[test]
    fn test_login_totp_invalid() {
        let db = DATABASE.lock().unwrap();
        db.add_user(
            "gil2@demo.ch",
            &compute_password_hash("gil2@demo.ch", "coucou").server_auth_password,
            Some("abcd"),
        )
        .unwrap();
        let session = Session::login("gil2@demo.ch", "coucou", Some("123456"));
        assert!(session.is_err(), "{:?}", session);
        assert_eq!(ErrorMessage::InvalidTotpCode, session.unwrap_err());
    }

    #[test]
    fn test_add_password() {
        let db = DATABASE.lock().unwrap();
        db.add_user(
            "gil3@demo.ch",
            &compute_password_hash("gil3@demo.ch", "coucou").server_auth_password,
            None,
        )
        .unwrap();
        let mut session = Session::login("gil3@demo.ch", "coucou", None).unwrap();
        assert_eq!(0, session.registry.entries.len());
        let res = session.add_password("hello", "demo", "1234");
        assert_eq!(1, session.registry.entries.len());
        assert!(res.is_ok());
    }

    #[test]
    fn test_delete_password() {
        let db = DATABASE.lock().unwrap();
        db.add_user(
            "gil4@demo.ch",
            &compute_password_hash("gil4@demo.ch", "coucou").server_auth_password,
            None,
        )
        .unwrap();
        let mut session = Session::login("gil4@demo.ch", "coucou", None).unwrap();
        session.add_password("hello", "demo", "1234").unwrap();
        assert_eq!(1, session.registry.entries.len());
        let res = session.delete_password(0);
        assert!(res.is_ok());
        assert_eq!(0, session.registry.entries.len());
    }
}
