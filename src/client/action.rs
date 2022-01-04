// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Client facade

use sodiumoxide::crypto::aead::Key;
use khape::{Client, Parameters, ExportKey, OutputKey};

use crate::client::hash::compute_password_hash;
use crate::common::error_message::ErrorMessage;
use crate::server::endpoint::{download,  upload, login_khape_start, login_khape_finish, register_khape_finish, register_khape_start};
use crate::common::password_registry::{OpenedEnvelope, PasswordEntry};

#[derive(Debug)]
pub struct Session {
    session_key: String,
    pub envelope: OpenedEnvelope,
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
        let (session_key, ek) = Session::login_khape(email, password)?;
        let session_token = base64::encode(session_key);
        let export_key = Key::from_slice(ek.as_ref()).unwrap(); // TODO
        let mut protected_envelope = download(&session_token)?;

        if protected_envelope.is_empty() {
            protected_envelope.initialize(&export_key);
            upload(&session_token, protected_envelope.clone())?;
        }

        let envelope = protected_envelope.open(&export_key)?;

        Ok(Session {
            session_key: session_token,
            envelope,
        })
    }

    fn login_khape(email: &str, password: &str) -> Result<(OutputKey, ExportKey), ErrorMessage> {
        let params = Parameters::default();
        let client = Client::new(params, String::from(email));

        let (auth_request, oprf_client_state) = client.auth_start(password.as_ref());
        let auth_response = login_khape_start(auth_request)?;
        let (auth_verify_request, ke_output, export_key) = client.auth_ke(auth_response, oprf_client_state);
        let auth_verify_response = login_khape_finish(auth_verify_request)?;

        match client.auth_finish(auth_verify_response, ke_output) {
            None => Err(ErrorMessage::AuthFailed),
            Some(output_key) => Ok((output_key, export_key))
        }
    }

    pub fn register_khape(email: &str, password: &str) -> Result<(), ErrorMessage> {
        let params = Parameters::default();
        let client = Client::new(params, String::from(email));

        let (register_request, oprf_client_state) = client.register_start(password.as_ref());
        let register_response = register_khape_start(register_request)?;
        let (register_finish, _) = client.register_finish(register_response, oprf_client_state);
        register_khape_finish(register_finish)?;

        Ok(())
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
        self.envelope.registry.entries.push(PasswordEntry::new(
            label.to_owned(),
            username.to_owned(),
            password.to_owned(),
            &self.envelope.internal_encryption_key
        ));
        self.seal_and_send()
    }

    /// Modify given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be modified. Ok(()) otherwise
    pub fn modify_password(
        &mut self,
        index: usize,
        label: &str,
        username: &str,
        password: &str,
    ) -> Result<(), ErrorMessage> {
        if self.envelope.registry.entries.get(index).is_some() {
            return Err(ErrorMessage::PasswordEntryNotFound);
        }

        self.delete_password(index);
        self.add_password(label, username, password);
        self.seal_and_send()?;
        Ok(())
    }

    /// Delete given password in the password manager.
    /// Encrypt password file and upload it to the server.
    ///
    /// Return ErrorMessage if the password cannot be deleted. Ok(()) otherwise
    pub fn delete_password(&mut self, index: usize) -> Result<(), ErrorMessage> {
        if self.envelope.registry.entries.get(index).is_some() {
            return Err(ErrorMessage::PasswordEntryNotFound);
        }

        self.envelope.registry.entries.remove(index);
        self.seal_and_send()
    }

    /// Encrypt the protected registry and send it to the server
    ///
    /// Return server's error if upload fail or Ok if successful
    fn seal_and_send(&self) -> Result<(), ErrorMessage> {
        let protected_envelope = self.envelope.seal();
        upload(&self.session_key, protected_envelope)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::server::repository::tests::DATABASE;

    #[test]
    fn test_register() {
        let db = DATABASE.lock().unwrap();
        let email = "test0@demo.com";
        let password = "password123";
        let register = Session::register_khape(email, password);
        assert!(register.is_ok());
    }

    #[test]
    fn test_login() {
        let db = DATABASE.lock().unwrap();
        let email = "test1@demo.com";
        let password = "password123";
        let register = Session::register_khape(email, password);
        assert!(register.is_ok());

        let session = Session::login(email, password, None);
        assert!(session.is_ok());
    }

    #[test]
    fn test_login_with_wrong_password() {
        let db = DATABASE.lock().unwrap();
        let email = "test2@demo.com";
        let password1 = "password123";
        let password2 = "qwertz";
        let register = Session::register_khape(email, password1);
        assert!(register.is_ok());

        let session = Session::login(email, password2, None);
        assert!(session.is_err());
    }


    #[test]
    fn test_login_failed() {
        DATABASE.lock().ok();
        let session = Session::login("test3@demo.ch", "password123", None);
        assert!(session.is_err(), "{:?}", session);
        assert_eq!(ErrorMessage::AuthFailed, session.unwrap_err());
    }

    // #[test]
    // fn test_login_failed_totp() {
    //     let db = DATABASE.lock().unwrap();
    //     db.add_user(
    //         "gil1@demo.ch",
    //         &compute_password_hash("gil1@demo.ch", "coucou").server_auth_password,
    //         Some("abcd"),
    //     )
    //     .unwrap();
    //     let session = Session::login("gil1@demo.ch", "coucou", None);
    //     assert!(session.is_err(), "{:?}", session);
    //     assert_eq!(ErrorMessage::TotpRequired, session.unwrap_err());
    // }
    //
    // #[test]
    // fn test_login_totp_invalid() {
    //     let db = DATABASE.lock().unwrap();
    //     db.add_user(
    //         "gil2@demo.ch",
    //         &compute_password_hash("gil2@demo.ch", "coucou").server_auth_password,
    //         Some("abcd"),
    //     )
    //     .unwrap();
    //     let session = Session::login("gil2@demo.ch", "coucou", Some("123456"));
    //     assert!(session.is_err(), "{:?}", session);
    //     assert_eq!(ErrorMessage::InvalidTotpCode, session.unwrap_err());
    // }

    #[test]
    fn test_add_password() {
        let db = DATABASE.lock().unwrap();
        Session::register_khape("test4@demo.com", "password123");
        let mut session = Session::login("test4@demo.com", "password123", None).unwrap();

        assert_eq!(0, session.envelope.registry.entries.len());
        let res = session.add_password("hello", "demo", "1234");
        assert_eq!(1, session.envelope.registry.entries.len());
        assert!(res.is_ok());
    }

    #[test]
    fn test_delete_password() {
        let db = DATABASE.lock().unwrap();
        Session::register_khape("test5@demo.com", "password123");
        let mut session = Session::login("test5@demo.com", "password123", None).unwrap();

        session.add_password("hello", "demo", "1234").unwrap();
        assert_eq!(1, session.envelope.registry.entries.len());
        let res = session.delete_password(0);
        assert!(res.is_ok());
        assert_eq!(0, session.envelope.registry.entries.len());
    }
}
