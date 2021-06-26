pub struct ProtectedRegistry {
    encrypted_registry: Vec<u8>,
}

impl ProtectedRegistry {
    pub fn new(encrypted_registry: Vec<u8>) -> Self {
        ProtectedRegistry {
            encrypted_registry
        }
    }
}