//! SEC : Labo project - Authentication
//! Author : Julien Béguin & Gil Balsiger
//! Date : 26.06.2021
//!
//! Email validation

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref REGEX_EMAIL: Regex = Regex::new(r#"^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$"#).unwrap();
}

/// Email address syntactical validation
///
/// Return true if the given email address is valid, false otherwise
pub fn validate_email(email: &str) -> bool {
    REGEX_EMAIL.is_match(email.to_lowercase().as_str())
}

/// Email address store procedure
///
/// Return lowercase string
pub fn store(email: &str) -> String {
    email.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email_address() {
        assert!(validate_email("email@example.com"));
        assert!(validate_email("firstname.lastname@example.com"));
        assert!(validate_email("email@subdomain.example.com"));
        assert!(validate_email("firstname+lastname@example.com"));
        assert!(validate_email("email@123.123.123.123"));
        assert!(validate_email("email@[123.123.123.123]"));
        assert!(validate_email("1234567890@example.com"));
        assert!(validate_email("email@example-one.com"));
        assert!(validate_email("_______@example.com"));
        assert!(validate_email("email@example.name"));
        assert!(validate_email("email@example.museum"));
        assert!(validate_email("email@example.co.jp"));
        assert!(validate_email("firstname-lastname@example.com"));
    }

    #[test]
    fn test_invalid_email_address() {
        assert!(!validate_email("plainaddress"));
        assert!(!validate_email("#@%^%#$@#$@#.com"));
        assert!(!validate_email("@example.com"));
        assert!(!validate_email("Joe Smith <email@example.com>"));
        assert!(!validate_email("email.example.com"));
        assert!(!validate_email("email@example@example.com"));
        assert!(!validate_email(".email@example.com"));
        assert!(!validate_email("email.@example.com"));
        assert!(!validate_email("email..email@example.com"));
        assert!(!validate_email("あいうえお@example.com"));
        assert!(!validate_email("email@example.com (Joe Smith)"));
        assert!(!validate_email("email@example"));
        assert!(!validate_email("email@-example.com"));
        assert!(!validate_email("email@example..com"));
        assert!(!validate_email("Abc..123@example.com"));
    }

    #[test]
    fn test_email_store() {
        assert_eq!(store("JUlIeN@HeiG-Vd.cH"), "julien@heig-vd.ch");
        assert_eq!(store("JULIEN@HEIG-VD.CH"), "julien@heig-vd.ch");
        assert_eq!(store("julien@heig-vd.ch"), "julien@heig-vd.ch");

        assert_ne!(store("julien@heig.ch"), "julien@heig-vd.ch");
    }
}
