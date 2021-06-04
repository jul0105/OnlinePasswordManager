//! Password structs

pub struct PasswordIdentification {
    id: u32,
    label: String,
    username: String,
    password: String,
}

pub struct Password {
    id: PasswordIdentification,
    password: String,
}