table! {
    users (id) {
        id -> Integer,
        email -> Text,
        password_hash -> Text,
        role -> Text,
        totp_secret -> Nullable<Text>,
    }
}
