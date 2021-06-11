//! Provices TOTP for two factors authentication

use dialoguer::Input;
use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use qr_code::QrCode;

pub fn check_totp_code(secret: &str) {
    let auth = GoogleAuthenticator::new();
    let secret = secret.to_owned(); // Trick to pass the secret to the closure with static lifetime
    Input::<String>::new()
        .with_prompt("Enter 6 digits code")
        .validate_with(move |input: &String| -> Result<(), &str> {
            if auth.verify_code(secret.as_ref(), input, 3, 0) {
                Ok(())
            } else {
                Err("Invalid code. Please try again")
            }
        })
        .interact_text()
        .unwrap();
}

pub fn new_totp_secret(email: &str) -> String {
    let auth = GoogleAuthenticator::new();
    // let secret = auth.create_secret(32);
    let secret = String::from("abcdabcdabcdabcdabcdabcdabcdabcd");
    let qr_code = QrCode::new(format!(
        "otpauth://totp/{}?secret={}&issuer=Password manager",
        email, secret
    ))
    .unwrap();

    println!("{}", qr_code.to_string(false, 3));
    println!(
        "{}",
        auth.qr_code_url(
            &secret,
            &email,
            "Sec lab2",
            400,
            400,
            ErrorCorrectionLevel::Medium
        )
    );

    check_totp_code(&secret);

    return secret;
}