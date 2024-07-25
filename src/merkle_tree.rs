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

    /// Hash the provided bytes using SHA-256.
    fn hash(self, bytes: &[u8]) -> [u8; 32] {
        Hash::hash(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::str::Bytes;

    use super::*;

    #[test]
    fn test_hash_should_return_sha256_digest() {
        let input = "In a hole in the ground there lived a hobbit.".as_bytes();
        let expected_hash =
            hex::decode("38a76005681abd4a4f50a364d472016436f17e79778577ee5825580f06997202")
                .unwrap();
        let digest = MerkleTree::new().hash(input).to_vec();

        assert_eq!(digest, expected_hash)
    }
}
