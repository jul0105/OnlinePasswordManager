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
    let mut is_valid = true;

    let db = DatabaseConnection::new();

    // Hash password
    let hashed_password = password::store(password.as_bytes());

    // Check if the email, password pair exist in DB
    let totp_secret = match db.auth_user(email, hashed_password.as_str()) {
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

        // Store whole token in DB
        match db.get_user(email) {
            Ok(user) => db.add_token(&user, &token),
            Err(_) => return Err(ErrorMessage::ServerSideError)
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::{SqliteConnection, Connection};
    use std::env;
    use dotenv::dotenv;


    // This macro from `diesel_migrations` defines an `embedded_migrations` module
    // containing a function named `run`. This allows the example to be run and
    // tested without any outside setup of the database.
    embed_migrations!("migrations");


    /// Get a clean db connection to the test-specific DB environment
    fn get_test_db() -> DatabaseConnection {
        // Retrieve .env config
        dotenv().ok();
        // Get connection from the test sqlite db
        let database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
        let conn = SqliteConnection::establish(&database_url).expect("Impossible to connect to database");

        // Execute migration to have a clean db
        embedded_migrations::run(&conn).expect("Migration not possible to run");

        DatabaseConnection {
            conn,
        }
    }

    #[test]
    fn test() {
        let db = get_test_db();

        db.get_user("dwa");
    }
}