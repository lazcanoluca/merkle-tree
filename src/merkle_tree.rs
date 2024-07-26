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
    pub fn build<T: AsRef<[u8]>>(&self, items: &[T]) -> Self {
        todo!()
    }

    /// Compute the parent hash for the provided left and right hashes.
    fn merkle_parent(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let concat = [left.as_slice(), right.as_slice()].concat();

        self.hash(&concat)
    }

    /// Hash the provided bytes using SHA-256.
    /// Returns the hash as a 32 bytes array.
    fn hash(&self, bytes: &[u8]) -> [u8; 32] {
        Hash::hash(bytes)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_hash_should_return_sha256_digest() {
        let input = "In a hole in the ground there lived a hobbit.".as_bytes();
        let hash = MerkleTree::new().hash(input);

        assert_eq!(
            hash.to_vec(),
            hex::decode("38a76005681abd4a4f50a364d472016436f17e79778577ee5825580f06997202")
                .unwrap()
        );
    }

    #[test]
    fn test_merkle_parent_should_return_hash_of_concated_hashes() {
        let left_input = "In a hole in the ground ".as_bytes();
        let left_hash = MerkleTree::new().hash(left_input);
        assert_eq!(
            left_hash.to_vec(),
            hex::decode("0e692eea8afb6955c357130611417c8426b87c5210c6b5206d0caf60a3f069f9")
                .unwrap()
        );

        let right_input = "there lived a hobbit.".as_bytes();
        let right_hash = MerkleTree::new().hash(right_input);
        assert_eq!(
            right_hash.to_vec(),
            hex::decode("fd6914578ce0a0ac2eb1f679a3a8047878c728d6518f48a3f0eb18ee57cc5091")
                .unwrap()
        );

        let parent_hash = MerkleTree::new().merkle_parent(&left_hash, &right_hash);
        assert_eq!(
            parent_hash.to_vec(),
            hex::decode("e7dbb63c6671bdf7581e418da8feee175e86adc84adc8e123a30407dd8e730f3")
                .unwrap()
        );
    }
}
