// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! System's error message

use strum::EnumMessage;

#[derive(EnumMessage, Debug, PartialEq)]
pub enum ErrorMessage {
    #[strum(message = "2 factors authentication is required")]
    TotpRequired,

    #[strum(message = "2FA code is incorrect")]
    InvalidTotpCode,

    #[strum(message = "Incorrect email or password")]
    AuthFailed,

    #[strum(message = "Sorry, an error happened on our side")]
    ServerSideError,

    #[strum(message = "User not found")]
    NoUserFound,

    #[strum(message = "Token no longer valid")]
    TokenExpired,

    #[strum(message = "Decryption failed")]
    DecryptionFailed,

    #[strum(message = "Unable to parse data from server")]
    DeserializeError,

    #[strum(message = "Unable to found password entry.")]
    PasswordEntryNotFound,
}
