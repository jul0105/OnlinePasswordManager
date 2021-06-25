//! Server facade

use crate::common::encrypted_file::EncryptedFile;
use crate::common::error_message::ErrorMessage;

use crate::server::authentication::{password, authenticator, token};
use crate::server::repository;
use crate::server::models::User;
use diesel::result::Error;

use log::{error, warn, info};

/// Authenticate user to the server and generate session token
///
/// Return session token if successful authentication, Error message otherwise
pub fn authentication(email: &str, password: &str, totp_code: Option<&str>) -> Result<String, ErrorMessage> {
    // The entire authentication process is executed, even if invalid, to try to mitigate timing attack
    let mut is_valid = true;

    // Hash password
    let hashed_password = password::store(password.as_bytes());

    // Check if the email, password pair exist in DB
    let totp_secret = match repository::auth_user(email, hashed_password.as_str()) {
        Ok(user) => user.totp_secret,
        Err(_) => {
            is_valid = false;
            warn!("User {} failed to authenticate with the server. The provided email-password combination is not present in DB.", email);
            None
        }
    };

    // Check if the totp code match the user in DB
    match totp_secret {
        None => {} // Normal behavior. User opted out of 2FA
        Some(secret) => match totp_code {
            None => {
                is_valid = false;
                warn!("User {} didn't provide a required TOTP code during authentication with the server", email);
            }
            Some(code) => if !authenticator::verify_code(secret.as_str(), code) {
                is_valid = false;
                warn!("User {} provided an invalid TOTP code during authentication with the server", email);
            }
        }
    }

    if is_valid {
        // If yes, generate and return a session token
        let token = token::generate_token();
        // TODO Store whole token in DB


        info!("User {} successfully authenticated with the server.", email);

        Ok(token.token)
    } else {
        // If no, return a generic error message
        Err(ErrorMessage::AuthFailed)
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
