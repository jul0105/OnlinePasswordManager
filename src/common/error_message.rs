use strum::EnumMessage;

#[derive(EnumMessage, Debug)]
pub enum ErrorMessage {
    #[strum(message = "2 factors authentication is required")]
    TotpRequired,

    #[strum(message = "2FA code is incorrect")]
    InvalidTotpCode,

    #[strum(message = "Incorrect email or password")]
    AuthFailed,

    #[strum(message = "Sorry, an error happened on our side. Please try again.")]
    ServerSideError
}