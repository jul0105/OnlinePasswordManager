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
        let user = match db.get_user(email) {
            Ok(user) => user,
            Err(_) => return Err(ErrorMessage::ServerSideError)
        };

        // If yes, generate and return a session token
        let token = token::generate_token(user.id);

        // Store whole token in DB
        db.add_token(&token);

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
    use tempfile::TempDir;


    // This macro from `diesel_migrations` defines an `embedded_migrations` module
    // containing a function named `run`. This allows the example to be run and
    // tested without any outside setup of the database.
    embed_migrations!("migrations");


    /// Get a clean db connection to the test-specific DB environment
    fn get_test_db() -> (DatabaseConnection, TempDir) {
        // Create temporary dir where db will be stored
        let tmp_dir = tempfile::Builder::new()
            .prefix(env!("CARGO_PKG_NAME"))
            .rand_bytes(5)
            .tempdir()
            .expect("not possible to create tempfile");

        let db_path = tmp_dir.path().join("test.db");
        let conn = SqliteConnection::establish(db_path.to_str().unwrap()).expect("Unable to connect to database");

        // Execute migration to have a clean db
        embedded_migrations::run(&conn).expect("Migration not possible to run");

        // Return db and tempdir because the temp directory is deleted when this var is out of scope, making the db unusable.
        (DatabaseConnection {
            conn,
        }, tmp_dir)
    }

    #[test]
    fn test() {
        let (db, td) = get_test_db();

        assert!(db.add_user("julien@heig-vd.com", "password hash", None).is_ok());
        assert!(db.get_user("julien@heig-vd.com").is_ok());
    }

    #[test]
    fn test_add_token() {
        let (db, td) = get_test_db();

        let user_id = 0;
        let token = token::generate_token(user_id);

        db.add_token(&token);
        let token2 = db.get_user_tokens(user_id);
        assert!(token2.is_ok());
        assert_eq!(token, token2.unwrap());

        // TODO
        // let token3 = token::generate_token(user_id);
        //
        // db.add_token(&token3);
        // let token4 = db.get_user_tokens(user_id);
        // println!("{:?}", token4)
    }
}