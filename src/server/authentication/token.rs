/// SEC : Labo 2 - Authentication
/// Author : Julien Béguin
/// Date : 23.05.2021
///
/// Random token generation and verification

use std::time::{Duration, SystemTime};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

#[derive(PartialEq, Debug, Clone)]
pub struct Token {
    pub token: String,
    validity_start: SystemTime,
    validity_end: SystemTime,
}

// Token is valid during 24 hours minutes
const VALIDITY_DURATION: u64 = 24 * 60 * 60;
const TOKEN_LENGTH: usize = 64;

/// Generate a new random token
///
/// Return Token struct
pub fn generate_token() -> Token {
    // Validity date
    let validity_start = SystemTime::now();
    let validity_end = validity_start.checked_add(Duration::new(VALIDITY_DURATION, 0)).unwrap();

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
    }
}

/// Verify that a given token match the stored token and check token's time validity
///
/// Return true if shared token is valid, false otherwise
pub fn verify_token(shared_token: &str, stored_token: Option<&Token>) -> bool {
    // Generate default token to try to mitigate timing attack
    let default_token = generate_token();
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
    let now = SystemTime::now();
    if token.validity_start > now || now > token.validity_end {
        result = false;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token() {
        let token = generate_token();
        assert!(token.token.len() > 24);
        assert_eq!(token.validity_start + Duration::new(VALIDITY_DURATION, 0), token.validity_end);

        let now = SystemTime::now();
        assert!(token.validity_start <= now && now <= token.validity_end);

        let before = now - Duration::new(10, 0);
        assert!(!(token.validity_start <= before && before <= token.validity_end));

        let after = now + Duration::new(10 + VALIDITY_DURATION, 0);
        assert!(!(token.validity_start <= after && after <= token.validity_end));
    }

    #[test]
    fn test_verify_token() {
        let token1 = generate_token();
        let token2 = generate_token();

        assert!(verify_token(token1.token.as_str(), Some(&token1)));

        assert!(!verify_token("", Some(&token1)));
        assert!(!verify_token("test", Some(&token1)));
        assert!(!verify_token("D1tCRPxvvJoX518rskUcSmweYMQw09nT", Some(&token1)));
        assert!(!verify_token(token2.token.as_str(), Some(&token1)));

        assert!(!verify_token(token1.token.as_str(), None));
    }
}
