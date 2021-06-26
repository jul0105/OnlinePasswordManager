use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProtectedRegistry {
    protected_entries: Vec<u8>,
}

pub struct PasswordEntry {
    label: String,
    password: String,
}

impl ProtectedRegistry {
    pub fn new() -> Self {
        ProtectedRegistry {
            protected_entries: Vec::new(),
        }
    }
}
