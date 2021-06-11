table! {
    tokens (token) {
        token -> Text,
        expire_at -> Timestamp,
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
