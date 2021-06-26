/// SEC : Labo 2 - Authentication
/// Author : Julien Béguin
/// Date : 23.05.2021
///
/// Random token generation and verification

use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use chrono::{NaiveDateTime, Utc, Duration};

use crate::server::models::Token;

// Token is valid during 24 hours minutes
const VALIDITY_DURATION: i64 = 24 * 60 * 60;
const TOKEN_LENGTH: usize = 64;

/// Generate a new random token
///
/// Return Token struct
pub fn generate_token(user_id: i32) -> Token {
    // Validity date
    let validity_start = Utc::now().naive_utc();
    let validity_end = validity_start.checked_add_signed(Duration::seconds(VALIDITY_DURATION)).unwrap();

    // Generate random token
    let token: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(TOKEN_LENGTH)
        .map(char::from)
        .collect();

    Token {
        token,
        validity_start,
        validity_end,
        user_id,
    }
}

/// Verify that a given token match the stored token and check token's time validity
///
/// Return true if shared token is valid, false otherwise
pub fn verify_token(user_id: i32, shared_token: &str, stored_token: Option<&Token>) -> bool {
    // Generate default token to try to mitigate timing attack
    let default_token = generate_token(user_id);
    let mut result = true;

    // Get stored token
    let token = match stored_token {
        None => {
            result = false;
            &default_token
        }
        Some(val) => val,
    };

    // token must be equal
    if token.token != shared_token {
        result = false;
    }

    // Check validity time
    let now = Utc::now().naive_utc();
    if token.validity_start > now || now > token.validity_end {
        result = false;
    }

    // Check user
    if token.user_id != user_id {
        result = false;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token = generate_token(0);
        assert!(token.token.len() > 24);
        assert_eq!(token.validity_start + Duration::seconds(VALIDITY_DURATION), token.validity_end);

        let now = Utc::now().naive_utc();
        assert!(token.validity_start <= now && now <= token.validity_end);

        let before = now - Duration::seconds(10);
        assert!(!(token.validity_start <= before && before <= token.validity_end));

        let after = now + Duration::seconds(10 + VALIDITY_DURATION);
        assert!(!(token.validity_start <= after && after <= token.validity_end));
    }

    #[test]
    fn test_verify_token() {
        let token1 = generate_token(0);
        let token2 = generate_token(0);

        assert!(verify_token(0, token1.token.as_str(), Some(&token1)));

        assert!(!verify_token(0, "", Some(&token1)));
        assert!(!verify_token(0, "test", Some(&token1)));
        assert!(!verify_token(0, "D1tCRPxvvJoX518rskUcSmweYMQw09nT", Some(&token1)));
        assert!(!verify_token(0, token2.token.as_str(), Some(&token1)));

        assert!(!verify_token(0, token1.token.as_str(), None));

        assert!(!verify_token(1, token1.token.as_str(), Some(&token1)));
    }
}
