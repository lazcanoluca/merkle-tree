use hmac_sha256::Hash;

pub struct MerkleTree {
    pub root: Option<[u8; 32]>,
    pub leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Create a new empty MerkleTree instance.
    pub fn new() -> Self {
        Self {
            root: None,
            leaves: Vec::new(),
        }
    }

    /// Create a new MerkleTree from the provided items.
    /// Each item should be representable as bytes.
    /// It returns a `MerkleTree` instance with the leaf hashes and the Merkle root.
    pub fn build<T: AsRef<[u8]>>(&self, items: &[T]) -> Self {
        let leaves: Vec<[u8; 32]> = items.iter().map(|item| self.hash(item.as_ref())).collect();

        Self {
            root: Some(self.merkle_root(leaves.clone())),
            leaves,
        }
    }

    /// Computes the parent hash for the concatenation of the provided left and right hashes.
    fn merkle_parent(&self, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let concat = [left.as_slice(), right.as_slice()].concat();

        self.hash(&concat)
    }

    /// Creates the parent level for the given level.
    /// If the level has an odd number of hashes, the last hash is duplicated.
    fn merkle_parent_level(&self, mut level: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
        // If the number of leafs is odd, duplicate the last leaf.
        if level.len() % 2 == 1 {
            level.extend(level.last().cloned())
        }

        level
            .chunks_exact(2)
            .map(|chunk| self.merkle_parent(&chunk[0], &chunk[1]))
            .collect()
    }

    /// Computes the Merkle root hash for the provided leaf hashes.
    fn merkle_root(&self, leafs: Vec<[u8; 32]>) -> [u8; 32] {
        let mut level = leafs;

        while level.len() > 1 {
            level = self.merkle_parent_level(level);
        }

        level[0]
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

    #[test]
    fn test_even_length_level_should_return_parent_level() {
        let merkle_tree = MerkleTree::new();

        let hashes = vec![
            merkle_tree.hash("Home is behind, the world ahead,".as_bytes()),
            merkle_tree.hash("and there are many paths to tread".as_bytes()),
            merkle_tree.hash("through shadows to the edge of night,".as_bytes()),
            merkle_tree.hash("until the stars are all alight.".as_bytes()),
        ];

        let parent_level = merkle_tree.merkle_parent_level(hashes.clone());

        assert_eq!(parent_level.len(), 2);
        assert_eq!(
            parent_level[0].to_vec(),
            merkle_tree
                .merkle_parent(&hashes.clone()[0], &hashes.clone()[1])
                .to_vec()
        );
        assert_eq!(
            parent_level[1].to_vec(),
            merkle_tree
                .merkle_parent(&hashes.clone()[2], &hashes.clone()[3])
                .to_vec()
        );
    }

    #[test]
    fn test_odd_length_level_should_return_parent_level() {
        let merkle_tree = MerkleTree::new();

        let hashes = vec![
            merkle_tree.hash("One ring to rule them all,".as_bytes()),
            merkle_tree.hash("One ring to find them,".as_bytes()),
            merkle_tree.hash("One ring to bring them all,".as_bytes()),
            merkle_tree.hash("and in the darkness bind them.".as_bytes()),
            merkle_tree.hash("In the Land of Mordor where the Shadows lie.".as_bytes()),
        ];

        let parent_level = merkle_tree.merkle_parent_level(hashes.clone());

        assert_eq!(parent_level.len(), 3);
        assert_eq!(
            parent_level[0].to_vec(),
            merkle_tree
                .merkle_parent(&hashes.clone()[0], &hashes.clone()[1])
                .to_vec()
        );
        assert_eq!(
            parent_level[1].to_vec(),
            merkle_tree
                .merkle_parent(&hashes.clone()[2], &hashes.clone()[3])
                .to_vec()
        );
        assert_eq!(
            parent_level[2].to_vec(),
            merkle_tree
                .merkle_parent(&hashes.clone()[4], &hashes.clone()[4])
                .to_vec()
        );
    }

    #[test]
    fn test_merkle_root_should_return_root_hash_one_level() {
        let merkle_tree = MerkleTree::new();

        let hashes = vec![
            merkle_tree.hash("The Road goes ever on and on,".as_bytes()),
            merkle_tree.hash("Down from the door where it began.".as_bytes()),
        ];

        let root_hash = merkle_tree.merkle_root(hashes.clone());

        assert_eq!(
            root_hash.to_vec(),
            merkle_tree.merkle_parent(&hashes.clone()[0], &hashes.clone()[1])
        );
    }

    #[test]
    fn test_merkle_root_should_return_root_hash_two_levels() {
        let merkle_tree = MerkleTree::new();

        let hashes = vec![
            merkle_tree.hash("One Ring to rule them all, One Ring to find them,".as_bytes()),
            merkle_tree
                .hash("One Ring to bring them all and in the darkness bind them.".as_bytes()),
            merkle_tree.hash("In the Land of Mordor where the Shadows lie.".as_bytes()),
        ];

        let root_hash = merkle_tree.merkle_root(hashes.clone());

        assert_eq!(
            root_hash.to_vec(),
            merkle_tree.merkle_parent(
                &merkle_tree.merkle_parent(&hashes.clone()[0], &hashes.clone()[1]),
                &merkle_tree.merkle_parent(&hashes.clone()[2], &hashes.clone()[2]),
            )
        );
    }
}
