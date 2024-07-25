use hmac_sha256::Hash;

pub struct MerkleTree {}

impl Default for MerkleTree {
    fn default() -> Self {
        Self {}
    }
}

impl MerkleTree {
    /// Create a new MerkleTree instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new MerkleTree from the provided items.
    /// Each item should be representable as bytes.
    pub fn build<T: AsRef<[u8]>>(self, items: &[T]) -> Self {
        todo!()
    }
}
