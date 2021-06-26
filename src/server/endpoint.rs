//! Server facade

use crate::common::error_message::ErrorMessage;

use crate::server::authentication::{password, token, totp};

use base64::read;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use log::{info, warn};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use crate::common::protected_registry::ProtectedRegistry;

use super::repository::DatabaseConnection;

fn authenticate(
    db: &DatabaseConnection,
    email: &str,
    password: &str,
    totp_code: Option<&str>,
) -> Result<String, ErrorMessage> {
    // The entire authentication process is executed, even if invalid, to try to mitigate timing attack
    let mut result = Ok(String::from(""));

    // Get user from DB
    let user = match db.get_user(email) {
        Ok(user) => user,
        Err(_) => {
            warn!("User {} failed to authenticate with the server. The provided email-password combination is not present in DB.", email);
            return Err(ErrorMessage::AuthFailed);
        }
    };

    // Hash password
    if !password::verify(&user.password_hash, password) {
        warn!(
            "User {} failed to authenticate with the server. Incorrect password",
            email
        );
        return Err(ErrorMessage::AuthFailed);
    }

    // Check if the totp code match the user in DB
    match user.totp_secret {
        None => {} // Normal behavior. User opted out of 2FA
        Some(secret) => match totp_code {
            None => {
                result = Err(ErrorMessage::AuthFailed);
                warn!("User {} didn't provide a required TOTP code during authentication with the server", email);
            }
            Some(code) => {
                if !totp::verify_code(secret.as_str(), code) {
                    result = Err(ErrorMessage::AuthFailed);
                    warn!("User {} provided an invalid TOTP code during authentication with the server", email);
                }
            }
        },
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

/// Authenticate user to the server and generate session token
///
/// Return session token if successful authentication, Error message otherwise
pub fn authentication(
    email: &str,
    password: &str,
    totp_code: Option<&str>,
) -> Result<String, ErrorMessage> {
    authenticate(&DatabaseConnection::new(), email, password, totp_code)
}

/// Download user's encrypted password file
///
/// Return encrypted file if session token is valid and user has permission to read the file. ErrorMessage otherwise
pub fn download(session_token: &str) -> Result<ProtectedRegistry, ErrorMessage> {
    let db = DatabaseConnection::new();

    match db.get_user_from_token(session_token) {
        Ok(user) => match File::open(Path::new("server_data").join(user.id.to_string())) {
            Ok(file) => {
                let mut buffer = Vec::new();
                let mut reader = DeflateDecoder::new(BufReader::new(file));
                reader.read_to_end(&mut buffer).unwrap();
                return Ok(bincode::deserialize(&buffer).unwrap());
            }
            Err(_) => {
                // Create empty ProjectedRegistry
                let registry = ProtectedRegistry::new();
                store_protected_registry(user.id, &registry, Path::new("server_data"))?;
                return Ok(registry);
            }
        },
        Err(error) => return Err(error),
    }
}

/// Upload (Override) user's stored password file with the given encrypted file
///
/// Return Ok if upload successful. ErrorMessage otherwise
pub fn upload(
    session_token: &str,
    protected_registry: ProtectedRegistry,
) -> Result<(), ErrorMessage> {
    let db = DatabaseConnection::new();

    match db.get_user_from_token(session_token) {
        Ok(user) => {
            store_protected_registry(user.id, &protected_registry, Path::new("server_data"))?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Serialize, compress and store the protected registry
fn store_protected_registry(
    user_id: i32,
    registry: &ProtectedRegistry,
    folder: &Path,
) -> Result<(), ErrorMessage> {
    let new_registry_file = File::create(folder.join(user_id.to_string())).unwrap();
    let serialized_registry = bincode::serialize(&registry).unwrap();
    let mut writer = DeflateEncoder::new(BufWriter::new(new_registry_file), Compression::default());
    writer.write_all(&serialized_registry).unwrap();
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::server::repository::tests::DATABASE;
    use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

    pub fn init_logger() {
        TermLogger::init(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Stdout,
            ColorChoice::Auto,
        )
        .unwrap();
    }

    #[test]
    fn test_authentication() {
        let db = DATABASE.lock().unwrap();

        let qres = db.add_user("albert@heig-vd.ch", "123456789", None);
        assert!(qres.is_ok());
        assert!(db.get_user("albert@heig-vd.ch").is_ok());

        let auth = authenticate(&db, "albert@heig-vd.ch", "123456789", None);
        assert!(auth.is_ok(), "{:?}", auth);

        assert!(authenticate(&db, "albert@he.ch", "123456789", None).is_err());
        assert!(authenticate(&db, "albert@heig-vd.ch", "1234", None).is_err());
    }
}
