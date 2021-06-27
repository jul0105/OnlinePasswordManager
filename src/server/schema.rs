// SEC : Labo project - Authentication
// Author : Julien Béguin & Gil Balsiger
// Date : 26.06.2021
//
//! Diesel DB macro

table! {
    tokens (token) {
        token -> Text,
        validity_start -> Timestamp,
        validity_end -> Timestamp,
        user_id -> Integer,
    }
}

table! {
    users (id) {
        id -> Integer,
        email -> Text,
        password_hash -> Text,
        role -> Text,
        totp_secret -> Nullable<Text>,
    }
}

joinable!(tokens -> users (user_id));

allow_tables_to_appear_in_same_query!(
    tokens,
    users,
);
