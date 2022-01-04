// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Server facade

use crate::common::error_message::ErrorMessage;

use crate::server::authentication::{password, token, totp};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use log::{info, warn, error};
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use super::repository::DatabaseConnection;
use khape::{AuthRequest, AuthResponse, AuthVerifyRequest, AuthVerifyResponse, RegisterRequest, RegisterResponse, RegisterFinish, Server, Parameters};
use crate::server::authentication::token::generate_token_from_key;
use crate::common::password_registry::ProtectedEnvelope;

fn authenticate(
    db: &DatabaseConnection,
    email: &str,
    password: &str,
    totp_code: Option<&str>,
) -> Result<String, ErrorMessage> {
    unimplemented!();
    /*

    // The entire authentication process is executed, even if invalid, to try to mitigate timing attack
    let mut result = Ok(String::from(""));

    // Get user from DB
    let user = match db.get_user(email) {
        Ok(user) => user,
        Err(_) => {
            warn!("User {} is not present in DB.", email);

            // Fake Argon2 for timing attacks
            password::verify("$argon2id$v=19$m=4096,t=3,p=1$spbfQIc9BCO2mWdMRMp3iQ$+tJffBAuOCQqKbVa9Db2P+zrQd6YbdTzxg41jY20odY", "demo");

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
                result = Err(ErrorMessage::TotpRequired);
                warn!("User {} didn't provide a required TOTP code during authentication with the server", email);
            }
            Some(code) => {
                if !totp::verify_code(&secret, code) {
                    result = Err(ErrorMessage::InvalidTotpCode);
                    warn!("User {} provided an invalid TOTP code during authentication with the server", email);
                }
            }
        },
    }

    if result.is_ok() {
        // If yes, generate and return a session token
        let token = token::generate_token(user.id);

        // Store whole token in DB
        if db.add_token(&token).is_err() {
            error!("Unable to store user {}'s session token in the server's DB.", user.email);
            return Err(ErrorMessage::ServerSideError);
        }

        info!("User {} successfully authenticated with the server.", email);
        Ok(token.token)
    } else {
        // If no, return a generic error message
        result
    }

     */
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

pub fn login_khape_start(auth_request: AuthRequest) -> Result<AuthResponse, ErrorMessage> {
    let db = DatabaseConnection::new();
    let server = Server::new(Parameters::default());
    let uid = auth_request.uid.clone();

    let file_entry = db.user_get_file_entry(&uid)?;

    let (auth_response, server_ephemeral_keys) = server.auth_start(auth_request, &file_entry);
    db.user_add_ephemeral_keys(&uid, server_ephemeral_keys);
    Ok(auth_response)
}

pub fn login_khape_finish(auth_verify_request: AuthVerifyRequest) -> Result<AuthVerifyResponse, ErrorMessage> {
    let db = DatabaseConnection::new();
    let server = Server::new(Parameters::default());
    let uid = auth_verify_request.uid.clone();


    let server_ephemeral_keys = db.user_get_ephemeral_keys(&uid)?;
    let file_entry = db.user_get_file_entry(&uid)?;

    let (auth_verify_response, server_output_key) = server.auth_finish(auth_verify_request, server_ephemeral_keys, &file_entry);
    if server_output_key.is_some() {
        let session_key = base64::encode(server_output_key.unwrap());
        let user = db.get_user(&uid)?;
        let session_token = token::generate_token_from_key(user.id, session_key);
        db.user_add_session_key(&uid, &session_token);
    }
    Ok(auth_verify_response)
}

pub fn register_khape_start(register_request: RegisterRequest) -> Result<RegisterResponse, ErrorMessage> {
    let db = DatabaseConnection::new();
    let server = Server::new(Parameters::default());
    let uid = register_request.uid.clone();

    let (register_response, pre_register_secrets) = server.register_start(register_request);
    db.pre_register_user(&uid, pre_register_secrets);
    Ok(register_response)
}

pub fn register_khape_finish(register_finish: RegisterFinish) -> Result<(), ErrorMessage> {
    let db = DatabaseConnection::new();
    let server = Server::new(Parameters::default());
    let uid = register_finish.uid.clone();

    let pre_register_secrets = db.user_get_pre_register_secrets(&uid)?;

    let file_entry = server.register_finish(register_finish, pre_register_secrets);

    db.finish_register_user(&uid, file_entry);

    Ok(())
}

/// Download user's encrypted password file
///
/// Return encrypted file if session token is valid and user has permission to read the file. ErrorMessage otherwise
pub fn download(session_key: &str) -> Result<ProtectedEnvelope, ErrorMessage> {
    let db = DatabaseConnection::new();

    match db.get_user_from_token(session_key) {
        Ok(user) => {
            info!("User {} authenticated successfully on the server with session token during download procedure.", user.email);
            match File::open(
                Path::new(&env::var("SERVER_DATA").expect("SERVER_DATA not set"))
                    .join(user.id.to_string()),
            ) {
                Ok(file) => {
                    let mut buffer = Vec::new();
                    let mut reader = DeflateDecoder::new(BufReader::new(file));
                    reader.read_to_end(&mut buffer).unwrap();
                    match bincode::deserialize(&buffer) {
                        Ok(data) => {
                            info!("User {} successfully downloaded its protected envelope from the server.", user.email);
                            Ok(data)
                        },
                        Err(_) => {
                            error!("Deserialization error happened while trying to download user {}'s protected envelope from the server.", user.email);
                            Err(ErrorMessage::DeserializeError)
                        },
                    }
                }
                Err(_) => {
                    info!("No protected envelope for user {}'s on the server. Creating a new one.", user.email);
                    // Create empty ProtectedEnvelope
                    let registry = ProtectedEnvelope::new();
                    store_protected_envelope(
                        user.id,
                        &registry,
                        Path::new(&env::var("SERVER_DATA").expect("SERVER_DATA not set")),
                    )?;
                    info!("New protected envelope created on the server for user {}.", user.email);
                    return Ok(registry);
                }
            }
        }
        Err(error) => {
            warn!("Download attempt failed on the server. The provided session token is not valid");
            return Err(error)
        },
    }
}

/// Upload (Override) user's stored password file with the given encrypted file
///
/// Return Ok if upload successful. ErrorMessage otherwise
pub fn upload(
    session_key: &str,
    protected_envelope: ProtectedEnvelope,
) -> Result<(), ErrorMessage> {
    let db = DatabaseConnection::new();

    match db.get_user_from_token(session_key) {
        Ok(user) => {
            info!("User {} authenticated successfully on the server with session token during upload procedure.", user.email);
            store_protected_envelope(
                user.id,
                &protected_envelope,
                Path::new(&env::var("SERVER_DATA").expect("SERVER_DATA not set")),
            )?;
            info!("User {} successfully uploaded its protected envelope to the server.", user.email);
            Ok(())
        }
        Err(e) => {
            warn!("Upload attempt failed on the server. The provided session token is not valid");
            Err(e)
        },
    }
}

/// Serialize, compress and store the protected envelope
fn store_protected_envelope(
    user_id: i32,
    protected_envelope: &ProtectedEnvelope,
    folder: &Path,
) -> Result<(), ErrorMessage> {
    let new_registry_file = match File::create(folder.join(user_id.to_string())) {
        Ok(val) => val,
        Err(_) => {
            error!("Unable to create file to store protected envelope for userid {} on the server", user_id);
            return Err(ErrorMessage::ServerSideError);
        },
    };

    let serialized_registry = match bincode::serialize(&protected_envelope) {
        Ok(val) => val,
        Err(_) => {
            error!("Unable to serialize protected envelope for userid {} on the server", user_id);
            return Err(ErrorMessage::ServerSideError);
        },
    };

    let mut writer = DeflateEncoder::new(BufWriter::new(new_registry_file), Compression::default());

    if let Err(_) = writer.write_all(&serialized_registry) {
        error!("Unable to write file to store protected envelope for userid {} on the server", user_id);
        return Err(ErrorMessage::ServerSideError);
    }

    info!("Successful store of protected envelope of userid {} on the server", user_id);
    Ok(())
}

pub fn register_new_user(
    email: &str,
    password: &str,
    totp_secret: Option<&str>,
) -> Result<String, String> {
    let db = DatabaseConnection::new();
    match db.add_user(email, password, totp_secret) {
        Ok(_) => {
            info!("User {} successfully registered on the server", email);
            return Ok(String::from("User successfully added"))
        },
        Err(e) => {
            error!("Unable to register user {} on the server's DB", email);
            return Err(format!(
                "Error while adding the user: {}. Please try again",
                e
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::repository::tests::DATABASE;

    #[test]
    fn test_endpoints() {
        let db = DATABASE.lock().unwrap();

        // Register
        let res = register_new_user("albert@heig-vd.ch", "123456789", None);
        assert!(res.is_ok());
        assert!(db.get_user("albert@heig-vd.ch").is_ok());

        // Authenticate
        let auth = authenticate(&db, "albert@heig-vd.ch", "123456789", None);
        assert!(auth.is_ok(), "{:?}", auth);

        assert!(authenticate(&db, "albert@he.ch", "123456789", None).is_err());
        assert!(authenticate(&db, "albert@heig-vd.ch", "1234", None).is_err());
    }
}
