/// SEC : Labo 2 - Authentication
/// Author : Julien Béguin
/// Date : 23.05.2021
///
/// Google authenticator interaction

use google_authenticator::{ErrorCorrectionLevel, GA_AUTH};

/// Generate a new 32-char long secret
///
/// Return secret String
pub fn generate_secret() -> String {
    google_authenticator::create_secret!()
}

/// Generate a QR-code URL containing the secret and, optional, the email address of the user
/// This QR-code can be used by the user to easily load the secret to his mobile app authenticator.
/// DISCLAIMER: Using this method, the secret is shared with a third party (Google) and
///             is transferred in plaintext in the URL (can be intercepted). Use with caution.
///
/// Return URL String
pub fn qr_code_url_from_secret(secret: &str, email: Option<&str>) -> String {
    google_authenticator::qr_code_url!(secret, email.unwrap_or("unnamed account"), "SEC Labo 2", 0, 0, ErrorCorrectionLevel::Medium)
}

/// Verify user's code from his authenticator using the shared secret
///
/// Return true if the code is valid, false otherwise
pub fn verify_code(secret: &str, code: &str) -> bool {
    google_authenticator::verify_code!(secret, code)
}


#[cfg(test)]
mod tests {
    use super::*;
    use google_authenticator::GoogleAuthenticator;

    #[test]
    fn test_generate_secret_length() {
        let secret1 = generate_secret();

        assert_eq!(secret1.len(), 32);
    }

    #[test]
    fn test_generate_different_secret() {
        let secret1 = generate_secret();
        let secret2 = generate_secret();

        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_qr_code_url_from_secret_without_email() {
        let secret = generate_secret();
        let url = qr_code_url_from_secret(secret.as_str(), None);

        assert!(url.contains(&secret));
    }

    #[test]
    fn test_qr_code_url_from_secret_with_email() {
        let secret = generate_secret();
        let url = qr_code_url_from_secret(secret.as_str(), Some("julien@heig-vd.ch"));

        assert!(url.contains(&secret));
        assert!(url.contains("julien"));
    }

    #[test]
    fn test_verify_valid_code() {
        let secret = generate_secret();
        let code = google_authenticator::get_code!(secret.as_str()).unwrap();

        assert!(verify_code(secret.as_str(), code.as_str()))
    }

    #[test]
    fn test_verify_code_with_different_times() {
        let secret = generate_secret();
        let auth = GoogleAuthenticator::new();
        let current_code = auth.get_code(secret.as_str(), 0).unwrap();
        let old_code = auth.get_code(secret.as_str(), 1).unwrap();

        assert_ne!(current_code, old_code);

        assert!(verify_code(secret.as_str(), current_code.as_str()));
        assert!(!verify_code(secret.as_str(), old_code.as_str()));
    }

    #[test]
    fn test_verify_static_code() {
        let secret = generate_secret();
        let code = "993746";

        assert!(!verify_code(secret.as_str(), code))
    }
}