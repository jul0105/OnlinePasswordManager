table! {
    tokens (session_key) {
        session_key -> Text,
        validity_start -> Timestamp,
        validity_end -> Timestamp,
        user_id -> Integer,
    }
}

table! {
    users (id) {
        id -> Integer,
        email -> Text,
        file_entry -> Nullable<Text>,
        pre_register_secrets -> Nullable<Text>,
        ephemeral_keys -> Nullable<Text>,
        role -> Text,
        totp_secret -> Nullable<Text>,
    }
}

joinable!(tokens -> users (user_id));

allow_tables_to_appear_in_same_query!(
    tokens,
    users,
);
