//! Server facade

use google_authenticator::GoogleAuthenticator;

use crate::common::encrypted_file::EncryptedFile;
use crate::common::error_message::ErrorMessage;

use super::repository::check_password;
use super::repository::get_user;
use super::repository::new_token;

/// Authenticate user to the server and generate session token
///
/// Return session token if successful authentication, Error message otherwise
pub fn authentication(
    email: &str,
    password: &str,
    totp_code: Option<&str>,
) -> Result<String, ErrorMessage> {
    // TODO add logging
    match get_user(email) {
        Ok(user) => {
            if check_password(&user, password) {
                if user.totp_secret.is_some() && totp_code.is_none() {
                    return Err(ErrorMessage::TotpRequired);
                } else {
                    // Check totp
                    if user.totp_secret.is_some() && totp_code.is_some() {
                        let auth = GoogleAuthenticator::new();
                        if !auth.verify_code(
                            &user.totp_secret.as_deref().unwrap(),
                            totp_code.unwrap(),
                            3,
                            0,
                        ) {
                            return Err(ErrorMessage::InvalidTotpCode);
                        }
                    }
                    return Ok(new_token(&user));
                }
            } else {
                return Err(ErrorMessage::AuthFailed);
            }
        }
        Err(_) => return Err(ErrorMessage::AuthFailed),
    }
}

/// Download user's encrypted password file
///
/// Return encrypted file if session token is valid and user has permission to read the file. ErrorMessage otherwise
pub fn download(session_token: &str) -> Result<EncryptedFile, ErrorMessage> {
    todo!();
}

/// Upload (Override) user's stored password file with the given encrypted file
///
/// Return Ok if upload successful. ErrorMessage otherwise
pub fn upload(session_token: &str, file_content: EncryptedFile) -> Result<(), ErrorMessage> {
    todo!();
}
