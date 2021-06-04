//! Server facade

use crate::common::encrypted_file::EncryptedFile;
use crate::common::error_message::ErrorMessage;

/// Authenticate user to the server and generate session token
///
/// Return session token if successful authentication, Error message otherwise
pub fn authentication(username: &str, password: &str, totp_code: &str) -> Result<String, ErrorMessage> {
    Err(ErrorMessage::ToImplement) // TODO implement
}

/// Download user's encrypted password file
///
/// Return encrypted file if session token is valid and user has permission to read the file. ErrorMessage otherwise
pub fn download(session_token: &str) -> Result<EncryptedFile, ErrorMessage> {
    Err(ErrorMessage::ToImplement) // TODO implement
}

/// Upload (Override) user's stored password file with the given encrypted file
///
/// Return Ok if upload successful. ErrorMessage otherwise
pub fn upload(session_token: &str, file_content: EncryptedFile) -> Result<(), ErrorMessage> {
    Err(ErrorMessage::ToImplement) // TODO implement
}