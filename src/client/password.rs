// Online Password Manager
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
// Modified on the 24.12.2021 by Julien Béguin
// For Bachelor Thesis KHAPE use case
//
//! Password verification

use zxcvbn::feedback;
use zxcvbn::zxcvbn;

const MAX_PASSWORD_CHAR: usize = 64; // Included
const MIN_PASSWORD_CHAR: usize = 8; // Included
const MIN_PASSWORD_SCORE: u8 = 3;


/// Validate that a given password fulfill password policy and is strong enough
///
/// Return Ok if password is valid, or Err with a String containing warning and suggestions
pub fn validate(password: &str) -> Result<(), String> {
    if !check_password_policy(password) {
        return Err(
            "Invalid password. Password must be between 8 and 64 characters long.".to_string(),
        );
    }

    match check_password_strength(password) {
        Ok(_) => Ok(()),
        Err(e) => match e {
            None => Err("Invalid password.".to_string()),
            Some(val) => {
                let mut error_message = format!("Invalid password. ");

                // Add warning
                match val.warning() {
                    None => {}
                    Some(warning) => error_message += format!("{} ", warning).as_str(),
                }

                // Add suggestions
                error_message += "\nSuggestions:";
                for elem in val.suggestions() {
                    error_message += format!("\n- {}", elem).as_str();
                }

                Err(error_message.to_owned())
            }
        },
    }
}

/// Check if password policy is fulfilled
/// Password must be between 8 (included) and 64 (included) chars long
///
/// Return true if policy is fulfilled
fn check_password_policy(password: &str) -> bool {
    password.len() >= MIN_PASSWORD_CHAR && password.len() <= MAX_PASSWORD_CHAR
}

/// Check password strength with zxcvbn lib.
/// Password must have a minimal score of 3 out of 4 to be accepted
///
/// Return Ok if the password is accepted, or Err with feedback suggestions
fn check_password_strength(password: &str) -> Result<(), Option<feedback::Feedback>> {
    let estimate: zxcvbn::Entropy = zxcvbn(password, &[]).unwrap();

    if estimate.score() >= MIN_PASSWORD_SCORE {
        Ok(())
    } else {
        Err(estimate.feedback().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate() {
        assert_eq!(validate("").is_ok(), false); // 0
        assert_eq!(validate("R").is_ok(), false); // 1
        assert_eq!(validate("RDK*").is_ok(), false); // 4
        assert_eq!(validate("RDK*Hda").is_ok(), false); // 7
        assert_eq!(validate("RDK*HdaL").is_ok(), false); // 8
        assert_eq!(validate("RDK*HdaLT*").is_ok(), true); // 10
        assert_eq!(validate("RDK*HdaLT*N94ckaReuHYcqWSW*Foz").is_ok(), true); // 30
        assert_eq!(
            validate("RDK*HdaLT*N94ckaReuHYcqWSW*FozVojA^$DRJeRMWz!PNa&sJqtz#tJp@q85s").is_ok(),
            true
        ); // 64
        assert_eq!(
            validate("RDK*HdaLT*N94ckaReuHYcqWSW*FozVojA^$DRJeRMWz!PNa&sJqtz#tJp@q85sw").is_ok(),
            true
        ); // 64
        assert_eq!(
            validate("RDK*HdaLT*N94ckaReuHYcqWSW*FozVojA^$DRJeRMWz!PNa&sJqtz#tJp@q85sww").is_ok(),
            false
        ); // 65
        assert_eq!(validate("RDK*HdaLT*N94ckaReuHYcqWSW*FozVojA^$DRJeRMWz!PNa&sJqtz#tJp@q85swwRD^JkMx3ft4n#MeQ5ACPB*LA6").is_ok(), false); // 90

        assert_eq!(validate("test").is_ok(), false);
        assert_eq!(validate("password").is_ok(), false);
        assert_eq!(validate("johnny123").is_ok(), false);
        assert_eq!(validate("admin").is_ok(), false);
        assert_eq!(validate("123456789").is_ok(), false);
        assert_eq!(validate("HeLlO").is_ok(), false);
        assert_eq!(validate("MorNiNg$$1").is_ok(), false);
        assert_eq!(validate("MorningVerifyTelevisionWood").is_ok(), true);
        assert_eq!(validate("Adw3iq$19nm2{d9ql!").is_ok(), true);
    }

    #[test]
    fn test_check_password_policy() {
        assert_eq!(check_password_policy(""), false); // 0
        assert_eq!(check_password_policy("0"), false); // 1
        assert_eq!(check_password_policy("0123"), false); // 4
        assert_eq!(check_password_policy("0123456"), false); // 7
        assert_eq!(check_password_policy("01234567"), true); // 8
        assert_eq!(check_password_policy("0123456789"), true); // 10
        assert_eq!(
            check_password_policy("012345678901234567890123456789"),
            true
        ); // 30
        assert_eq!(
            check_password_policy(
                "012345678901234567890123456789012345678901234567890123456789012"
            ),
            true
        ); // 63
        assert_eq!(
            check_password_policy(
                "0123456789012345678901234567890123456789012345678901234567890123"
            ),
            true
        ); // 64
        assert_eq!(
            check_password_policy(
                "01234567890123456789012345678901234567890123456789012345678901234"
            ),
            false
        ); // 65
        assert_eq!(
            check_password_policy(
                "0123456789012345678901234567890123456789012345678901234567890123456789"
            ),
            false
        ); // 70
    }

    #[test]
    fn test_check_password_strength() {
        assert_eq!(check_password_strength("test").is_ok(), false);
        assert_eq!(check_password_strength("password").is_ok(), false);
        assert_eq!(check_password_strength("johnny123").is_ok(), false);
        assert_eq!(check_password_strength("admin").is_ok(), false);
        assert_eq!(check_password_strength("123456789").is_ok(), false);
        assert_eq!(check_password_strength("HeLlO").is_ok(), false);
        assert_eq!(check_password_strength("MorNiNg$$1").is_ok(), false);
        assert_eq!(
            check_password_strength("MorningVerifyTelevisionWood").is_ok(),
            true
        );
        assert_eq!(check_password_strength("Adw3iq$19nm2{d9ql!").is_ok(), true);
    }
}
