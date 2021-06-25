/// SEC : Labo 2 - Authentication
/// Author : Julien Béguin
/// Date : 23.05.2021
///
/// Email validation

use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref REGEX_EMAIL: Regex = Regex::new(r#"^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$"#).unwrap();
}

 /// Email address syntactical validation
 ///
 /// Return true if the given email address is valid, false otherwise
pub fn validate(email: &str) -> bool {
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
        assert!(validate("email@example.com"));
        assert!(validate("firstname.lastname@example.com"));
        assert!(validate("email@subdomain.example.com"));
        assert!(validate("firstname+lastname@example.com"));
        assert!(validate("email@123.123.123.123"));
        assert!(validate("email@[123.123.123.123]"));
        assert!(validate("1234567890@example.com"));
        assert!(validate("email@example-one.com"));
        assert!(validate("_______@example.com"));
        assert!(validate("email@example.name"));
        assert!(validate("email@example.museum"));
        assert!(validate("email@example.co.jp"));
        assert!(validate("firstname-lastname@example.com"));
    }

    #[test]
    fn test_invalid_email_address() {
        assert!(!validate("plainaddress"));
        assert!(!validate("#@%^%#$@#$@#.com"));
        assert!(!validate("@example.com"));
        assert!(!validate("Joe Smith <email@example.com>"));
        assert!(!validate("email.example.com"));
        assert!(!validate("email@example@example.com"));
        assert!(!validate(".email@example.com"));
        assert!(!validate("email.@example.com"));
        assert!(!validate("email..email@example.com"));
        assert!(!validate("あいうえお@example.com"));
        assert!(!validate("email@example.com (Joe Smith)"));
        assert!(!validate("email@example"));
        assert!(!validate("email@-example.com"));
        assert!(!validate("email@example..com"));
        assert!(!validate("Abc..123@example.com"));
    }

    #[test]
    fn test_email_store() {
        assert_eq!(store("JUlIeN@HeiG-Vd.cH"), "julien@heig-vd.ch");
        assert_eq!(store("JULIEN@HEIG-VD.CH"), "julien@heig-vd.ch");
        assert_eq!(store("julien@heig-vd.ch"), "julien@heig-vd.ch");

        assert_ne!(store("julien@heig.ch"), "julien@heig-vd.ch");
    }
}