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
    pub fn build<T: AsRef<[u8]>>(items: &[T]) -> Option<Self> {
        if items.is_empty() {
            return None;
        }

        let leaves: Vec<[u8; 32]> = items.iter().map(|item| Self::hash(item.as_ref())).collect();

        Some(Self {
            root: Some(Self::merkle_root(leaves.clone())),
            leaves,
        })
    }

    /// Computes the parent hash for the concatenation of the children hashes.
    fn merkle_parent(children: &[[u8; 32]]) -> [u8; 32] {
        Self::hash(children.as_flattened())
    }

    /// Creates the parent level for the given level.
    /// If the level has an odd number of hashes, the last hash is duplicated.
    fn merkle_parent_level(mut level: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
        // If the number of leafs is odd, duplicate the last leaf.
        if level.len() % 2 == 1 {
            level.extend(level.last().cloned())
        }

        level
            .chunks_exact(2)
            .map(|chunk| Self::merkle_parent(chunk))
            .collect()
    }

    /// Computes the Merkle root hash for the provided leaf hashes.
    fn merkle_root(leafs: Vec<[u8; 32]>) -> [u8; 32] {
        let mut level = leafs;

        while level.len() > 1 {
            level = Self::merkle_parent_level(level);
        }

        level[0]
    }

    /// Hash the provided bytes using SHA-256.
    /// Returns the hash as a 32 bytes array.
    fn hash(bytes: &[u8]) -> [u8; 32] {
        Hash::hash(bytes)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_hash_should_return_sha256_digest() {
        let input = "In a hole in the ground there lived a hobbit.".as_bytes();
        let hash = MerkleTree::hash(input);

        assert_eq!(
            hash.to_vec(),
            hex::decode("38a76005681abd4a4f50a364d472016436f17e79778577ee5825580f06997202")
                .unwrap()
        );
    }

    #[test]
    fn test_merkle_parent_should_return_hash_of_concated_hashes() {
        let left_input = "In a hole in the ground ".as_bytes();
        let left_hash = MerkleTree::hash(left_input);
        assert_eq!(
            left_hash.to_vec(),
            hex::decode("0e692eea8afb6955c357130611417c8426b87c5210c6b5206d0caf60a3f069f9")
                .unwrap()
        );

        let right_input = "there lived a hobbit.".as_bytes();
        let right_hash = MerkleTree::hash(right_input);
        assert_eq!(
            right_hash.to_vec(),
            hex::decode("fd6914578ce0a0ac2eb1f679a3a8047878c728d6518f48a3f0eb18ee57cc5091")
                .unwrap()
        );

        let parent_hash = MerkleTree::merkle_parent(&[left_hash, right_hash]);
        assert_eq!(
            parent_hash.to_vec(),
            hex::decode("e7dbb63c6671bdf7581e418da8feee175e86adc84adc8e123a30407dd8e730f3")
                .unwrap()
        );
    }

    #[test]
    fn test_even_length_level_should_return_parent_level() {
        let hashes = vec![
            MerkleTree::hash("Home is behind, the world ahead,".as_bytes()),
            MerkleTree::hash("and there are many paths to tread".as_bytes()),
            MerkleTree::hash("through shadows to the edge of night,".as_bytes()),
            MerkleTree::hash("until the stars are all alight.".as_bytes()),
        ];

        let parent_level = MerkleTree::merkle_parent_level(hashes.clone());

        assert_eq!(parent_level.len(), 2);
        assert_eq!(
            parent_level[0].to_vec(),
            MerkleTree::merkle_parent(&[hashes[0], hashes[1]]).to_vec()
        );
        assert_eq!(
            parent_level[1].to_vec(),
            MerkleTree::merkle_parent(&[hashes[2], hashes[3]]).to_vec()
        );
    }

    #[test]
    fn test_odd_length_level_should_return_parent_level() {
        let hashes = vec![
            MerkleTree::hash("One ring to rule them all,".as_bytes()),
            MerkleTree::hash("One ring to find them,".as_bytes()),
            MerkleTree::hash("One ring to bring them all,".as_bytes()),
            MerkleTree::hash("and in the darkness bind them.".as_bytes()),
            MerkleTree::hash("In the Land of Mordor where the Shadows lie.".as_bytes()),
        ];

        let parent_level = MerkleTree::merkle_parent_level(hashes.clone());

        assert_eq!(parent_level.len(), 3);
        assert_eq!(
            parent_level[0].to_vec(),
            MerkleTree::merkle_parent(&[hashes[0], hashes[1]]).to_vec()
        );
        assert_eq!(
            parent_level[1].to_vec(),
            MerkleTree::merkle_parent(&[hashes[2], hashes[3]]).to_vec()
        );
        assert_eq!(
            parent_level[2].to_vec(),
            MerkleTree::merkle_parent(&[hashes[4], hashes[4]]).to_vec()
        );
    }

    #[test]
    fn test_merkle_root_should_return_root_hash_one_level() {
        let hashes = vec![
            MerkleTree::hash("The Road goes ever on and on,".as_bytes()),
            MerkleTree::hash("Down from the door where it began.".as_bytes()),
        ];

        let root_hash = MerkleTree::merkle_root(hashes.clone());

        assert_eq!(root_hash.to_vec(), MerkleTree::merkle_parent(&hashes));
    }

    #[test]
    fn test_merkle_root_should_return_root_hash_two_levels() {
        let hashes = vec![
            MerkleTree::hash("One Ring to rule them all, One Ring to find them,".as_bytes()),
            MerkleTree::hash(
                "One Ring to bring them all and in the darkness bind them.".as_bytes(),
            ),
            MerkleTree::hash("In the Land of Mordor where the Shadows lie.".as_bytes()),
        ];

        let root_hash = MerkleTree::merkle_root(hashes.clone());

        assert_eq!(
            root_hash.to_vec(),
            MerkleTree::merkle_parent(&[
                MerkleTree::merkle_parent(&[hashes[0], hashes[1]]),
                MerkleTree::merkle_parent(&[hashes[2], hashes[2]])
            ])
        );
    }

    #[test]
    fn test_build_with_no_items_returns_none() {
        let tree = MerkleTree::build(Vec::<&[u8]>::new().as_slice());
        assert!(tree.is_none());
    }
}
