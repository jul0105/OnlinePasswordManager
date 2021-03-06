// Online Password Manager
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
// Modified on the 24.12.2021 by Julien Béguin
// For Bachelor Thesis KHAPE use case
//
//! Random token generation and verification

use chrono::{Duration, Utc};

use crate::common::error_message::ErrorMessage;
use crate::server::models::Token;
use log::{warn};

// Token is valid during 24 hours minutes
const VALIDITY_DURATION: i64 = 24 * 60 * 60;

pub fn generate_token_from_key(user_id: i32, session_key: String) -> Token {
    // Validity date
    let validity_start = Utc::now().naive_utc();
    let validity_end = validity_start + Duration::seconds(VALIDITY_DURATION);

    Token {
        session_key,
        validity_start,
        validity_end,
        user_id,
    }
}


pub fn validate_token(token: &Token) -> Result<(), ErrorMessage> {
    let now = Utc::now().naive_utc();
    if now < token.validity_start || now > token.validity_end {
        warn!("Token validation failed. Expired token for userid {}", token.user_id);
        return Err(ErrorMessage::TokenExpired);
    } else {
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    const TOKEN_LENGTH: usize = 32;

    fn generate_token(user_id: i32) -> Token {
        // Generate random token
        let session_key: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(TOKEN_LENGTH)
            .map(char::from)
            .collect();

        generate_token_from_key(user_id, session_key)
    }

    #[test]
    fn test_generate_token() {
        let token = generate_token(0);
        assert!(token.session_key.len() > 24);
        assert_eq!(
            token.validity_start + Duration::seconds(VALIDITY_DURATION),
            token.validity_end
        );

        let now = Utc::now().naive_utc();
        assert!(token.validity_start <= now && now <= token.validity_end);

        let before = now - Duration::seconds(10);
        assert!(!(token.validity_start <= before && before <= token.validity_end));

        let after = now + Duration::seconds(10 + VALIDITY_DURATION);
        assert!(!(token.validity_start <= after && after <= token.validity_end));
    }

    #[test]
    fn test_validate_valid_token() {
        let token = generate_token(0);
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn test_validate_invalid_token() {
        let token = Token {
            session_key: String::new(),
            validity_start: Utc::now().naive_utc() - Duration::days(7),
            validity_end: Utc::now().naive_utc() - Duration::days(5),
            user_id: 0,
        };
        assert!(validate_token(&token).is_err());
    }

    #[test]
    fn test_validate_invalid_token2() {
        let token = Token {
            session_key: String::new(),
            validity_start: Utc::now().naive_utc() + Duration::days(7),
            validity_end: Utc::now().naive_utc() + Duration::days(5),
            user_id: 0,
        };
        assert!(validate_token(&token).is_err());
    }
}
