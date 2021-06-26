//! Server facade

use crate::common::encrypted_file::EncryptedFile;
use crate::common::error_message::ErrorMessage;

use crate::server::authentication::{password, authenticator, token};
use crate::server::repository;
use crate::server::models::User;
use diesel::result::Error;

use log::{error, warn, info};
use crate::server::repository::DatabaseConnection;

/// Authenticate user to the server and generate session token
///
/// Return session token if successful authentication, Error message otherwise
pub fn authentication(email: &str, password: &str, totp_code: Option<&str>) -> Result<String, ErrorMessage> {
    // The entire authentication process is executed, even if invalid, to try to mitigate timing attack
    let mut result = Ok(String::from(""));

    let db = DatabaseConnection::new();

    // Get user from DB
    let user = match db.get_user(email) {
        Ok(user) => user,
        Err(_) => {
            result = Err(ErrorMessage::AuthFailed);
            User {
                id: 0,
                email: "".to_string(),
                password_hash: "$argon2id$v=19$m=4096,t=3,p=1$A2ubGqu7J0TSzFEGvSgw8w$OKgETmokunLelwSj11SvKuz/dpI1qNnKvcRI8QNM8uo".to_string(),
                role: "user".to_string(),
                totp_secret: None
            }
        }
    };

    // Hash password
    if !password::verify(user.password_hash.as_str(), password.as_bytes()) {
        result = Err(ErrorMessage::AuthFailed);
        warn!("User {} failed to authenticate with the server. The provided email-password combination is not present in DB.", email);
    }

    // Check if the totp code match the user in DB
    match user.totp_secret {
        None => {} // Normal behavior. User opted out of 2FA
        Some(secret) => match totp_code {
            None => {
                result = Err(ErrorMessage::AuthFailed);
                warn!("User {} didn't provide a required TOTP code during authentication with the server", email);
            }
            Some(code) => if !authenticator::verify_code(secret.as_str(), code) {
                result = Err(ErrorMessage::AuthFailed);
                warn!("User {} provided an invalid TOTP code during authentication with the server", email);
            }
        }
    }

    if result.is_ok() {
        // If yes, generate and return a session token
        let token = token::generate_token(user.id);

        // Store whole token in DB
        db.add_token(&token);

        info!("User {} successfully authenticated with the server.", email);
        Ok(token.token)
    } else {
        // If no, return a generic error message
        result
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::repository::tests::get_test_db;
    use simplelog::{TermLogger, LevelFilter, Config, TerminalMode, ColorChoice};

    pub fn init_logger() {
        TermLogger::init(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Stdout,
            ColorChoice::Auto,
        ).unwrap();
    }
    #[test]
    fn test_authentication() {
        init_logger();
        let (db, td) = get_test_db();

        let qres = db.add_user("julien@heig-vd.ch", password::store("123456789".as_bytes()).as_str(), None);
        assert!(qres.is_ok());
        assert!(db.get_user("julien@heig-vd.ch").is_ok());

        assert!(authentication("julien@heig-vd.ch", "123456789", None).is_ok());

        assert!(authentication("julien@he.ch", "123456789", None).is_err());
        assert!(authentication("julien@heig-vd.ch", "1234", None).is_err());
    }
}