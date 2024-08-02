use hmac_sha256;

type Hash = [u8; 32];

struct TreePosition {
    level: usize,
    index: usize,
    hash: Hash,
}

pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Create a new MerkleTree from the provided items.
    /// Each item should be representable as bytes.
    /// The creation will fail if the items list is empty.
    ///
    /// # Examples
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let items = vec!["In a hole in the ground", "there lived a hobbit."];
    /// let merkle_tree = MerkleTree::build(&items).unwrap();
    /// ```
    pub fn build<T: AsRef<[u8]>>(items: &[T]) -> Option<Self> {
        if items.is_empty() {
            return None;
        }

        let leaves: Vec<Hash> = items.iter().map(|item| Self::hash(item.as_ref())).collect();

        let levels = Self::construct_levels(leaves);

        Some(Self { levels })
    }

    /// Insert a new item into the Merkle tree.
    /// The tree will be updated to include the new item's hash.
    ///
    /// # Examples
    /// ```
    /// use merkle_tree::MerkleTree;
    /// let items = vec!["In a hole in the ground", "there lived a hobbit."];
    /// let mut merkle_tree = MerkleTree::build(&items).unwrap();
    ///
    /// merkle_tree.insert(&"Gandalf the Grey");
    /// ```
    pub fn insert<T: AsRef<[u8]>>(&mut self, item: &T) {
        let mut leaves = self.levels[0].clone();
        leaves.push(Self::hash(item.as_ref()));

        let levels = Self::construct_levels(leaves);

        self.levels = levels;
    }

    fn construct_levels(leaves: Vec<Hash>) -> Vec<Vec<Hash>> {
        let total_height = Self::tree_height(leaves.len());

        let mut levels = Vec::with_capacity(total_height + 1);

        levels.push(leaves);

        while let Some(level) = Self::merkle_parent_level(levels.last().unwrap()) {
            levels.push(level);
        }

        levels
    }

    fn tree_height(items: usize) -> usize {
        (items as f64).log2().ceil() as usize
    }

    /// Computes the parent hash for the concatenation of the children hashes.
    fn merkle_parent(children: &[Hash]) -> Hash {
        let mut children_vector = children.to_vec();
        children_vector.sort();
        Self::hash(children_vector.as_flattened())
    }

    /// Creates the parent level for the given level.
    /// If the level has an odd number of hashes, the last hash is duplicated.
    fn merkle_parent_level(level: &Vec<Hash>) -> Option<Vec<Hash>> {
        // Is root, return None.
        if level.len() == 1 {
            return None;
        }

        // If the number of leafs is odd, duplicate the last leaf.
        let mut parent_level = level.clone();

        if level.len() % 2 == 1 {
            parent_level.extend(parent_level.last().cloned())
        }

        Some(
            parent_level
                .chunks_exact(2)
                .map(Self::merkle_parent)
                .collect(),
        )
    }

    /// Computes the Merkle root hash for the provided leaf hashes.
    pub fn root(&self) -> Hash {
        self.levels.last().unwrap().first().unwrap().clone()
    }

    /// Hash the provided bytes using SHA-256.
    /// Returns the hash as a 32 bytes array.
    ///
    /// # Examples
    /// ```
    /// use merkle_tree::MerkleTree;
    ///
    /// let input = "In a hole in the ground there lived a hobbit.";
    /// let hash = MerkleTree::hash(input.as_bytes());
    /// ```
    pub fn hash(bytes: &[u8]) -> Hash {
        hmac_sha256::Hash::hash(bytes)
    }

    // Returns tuple (level, index, hash).
    fn get_parent(&self, level: usize, index: usize) -> Option<TreePosition> {
        let parent_index = index / 2;
        let parent_level = level + 1;
        let parent = self.levels.get(parent_level)?.get(parent_index)?.clone();

        Some(TreePosition {
            level: parent_level,
            index: parent_index,
            hash: parent,
        })
    }

    fn get_sibling(&self, level: usize, index: usize) -> Option<TreePosition> {
        let sibling_index = if index % 2 == 1 { index - 1 } else { index + 1 };

        let sibling = self.levels.get(level)?.get(sibling_index)?.clone();

        Some(TreePosition {
            level: level,
            index: sibling_index,
            hash: sibling,
        })
    }

    pub fn proof_of_inclusion(&self, hash: &Hash) -> Option<Vec<Hash>> {
        let index = self.levels.get(0)?.iter().position(|&h| h == *hash)?;

        let mut current = TreePosition {
            level: 0,
            index,
            hash: hash.clone(),
        };

        let mut proof: Vec<Hash> = Vec::new();

        while let Some(parent) = self.get_parent(current.level, current.index) {
            let sibling = self.get_sibling(current.level, current.index);
            proof.push(sibling.or(Some(current)).unwrap().hash);
            current = parent;
        }

        Some(proof)
    }

    pub fn validate_proof(&self, hash: &Hash, proof: &[Hash]) -> bool {
        let validation_root = proof.iter().fold(hash.clone(), |hash, sibling| {
            Self::merkle_parent(&[hash, *sibling])
        });

        validation_root == self.root()
    }

    pub fn contains_hash(&self, hash: &Hash) -> bool {
        self.levels[0].iter().any(|h| h == hash)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_hash_should_return_sha256_digest() {
        let input = "In a hole in the ground there lived a hobbit.";
        let hash = MerkleTree::hash(input.as_bytes());
        let expected_hash =
            hex::decode("38a76005681abd4a4f50a364d472016436f17e79778577ee5825580f06997202")
                .unwrap();

        assert_eq!(hash.to_vec(), expected_hash);
    }

    #[test]
    fn test_merkle_parent_should_return_hash_of_concated_hashes() {
        let left_input = "In a hole in the ground ";
        let left_hash = MerkleTree::hash(left_input.as_bytes());

        let expected_left_hash =
            hex::decode("0e692eea8afb6955c357130611417c8426b87c5210c6b5206d0caf60a3f069f9")
                .unwrap();

        assert_eq!(left_hash.to_vec(), expected_left_hash);

        let right_input = "there lived a hobbit.";
        let right_hash = MerkleTree::hash(right_input.as_bytes());
        let expected_right_hash =
            hex::decode("fd6914578ce0a0ac2eb1f679a3a8047878c728d6518f48a3f0eb18ee57cc5091")
                .unwrap();

        assert_eq!(right_hash.to_vec(), expected_right_hash);

        let parent_hash = MerkleTree::merkle_parent(&[left_hash, right_hash]);
        let expected_parent_hash =
            hex::decode("e7dbb63c6671bdf7581e418da8feee175e86adc84adc8e123a30407dd8e730f3")
                .unwrap();

        assert_eq!(parent_hash.to_vec(), expected_parent_hash);
    }

    #[test]
    fn test_even_length_level_should_return_parent_level() {
        let hashes = vec![
            MerkleTree::hash("Home is behind, the world ahead,".as_bytes()),
            MerkleTree::hash("and there are many paths to tread".as_bytes()),
            MerkleTree::hash("through shadows to the edge of night,".as_bytes()),
            MerkleTree::hash("until the stars are all alight.".as_bytes()),
        ];

        let parent_level = MerkleTree::merkle_parent_level(&hashes);

        assert!(parent_level.is_some());
        assert_eq!(parent_level.clone().unwrap().len(), 2);
        assert_eq!(
            parent_level.clone().unwrap()[0].to_vec(),
            MerkleTree::merkle_parent(&[hashes[0], hashes[1]]).to_vec()
        );
        assert_eq!(
            parent_level.clone().unwrap()[1].to_vec(),
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

        let parent_level = MerkleTree::merkle_parent_level(&hashes);

        assert_eq!(parent_level.clone().unwrap().len(), 3);
        assert_eq!(
            parent_level.clone().unwrap()[0].to_vec(),
            MerkleTree::merkle_parent(&[hashes[0], hashes[1]]).to_vec()
        );
        assert_eq!(
            parent_level.clone().unwrap()[1].to_vec(),
            MerkleTree::merkle_parent(&[hashes[2], hashes[3]]).to_vec()
        );
        assert_eq!(
            parent_level.clone().unwrap()[2].to_vec(),
            MerkleTree::merkle_parent(&[hashes[4], hashes[4]]).to_vec()
        );
    }

    #[test]
    fn test_merkle_root_should_return_root_hash_one_level() {
        let items = vec![
            "The Road goes ever on and on,",
            "Down from the door where it began.",
        ];

        let hashes = vec![
            MerkleTree::hash(items[0].as_bytes()),
            MerkleTree::hash(items[1].as_bytes()),
        ];

        let root_hash = MerkleTree::build(&items).unwrap().root();

        assert_eq!(root_hash.to_vec(), MerkleTree::merkle_parent(&hashes));
    }

    #[test]
    fn test_merkle_root_should_return_root_hash_two_levels() {
        let items = vec![
            "One Ring to rule them all, One Ring to find them,",
            "One Ring to bring them all and in the darkness bind them.",
            "In the Land of Mordor where the Shadows lie.",
        ];

        let hashes = vec![
            MerkleTree::hash(items[0].as_bytes()),
            MerkleTree::hash(items[1].as_bytes()),
            MerkleTree::hash(items[2].as_bytes()),
        ];

        let root_hash = MerkleTree::build(&items).unwrap().root();

        assert_eq!(
            root_hash.to_vec(),
            MerkleTree::merkle_parent(&[
                MerkleTree::merkle_parent(&[hashes[0], hashes[1]]),
                MerkleTree::merkle_parent(&[hashes[2], hashes[2]])
            ])
        );
    }

    #[test]
    fn test_build_merkle_tree() {
        let items = vec![
            "One Ring to rule them all,",
            "One Ring to find them,",
            "One Ring to bring them all",
            "and in the darkness bind them.",
            "In the Land of Mordor where the Shadows lie.",
        ];

        let hashes = vec![
            MerkleTree::hash(items[0].as_bytes()),
            MerkleTree::hash(items[1].as_bytes()),
            MerkleTree::hash(items[2].as_bytes()),
            MerkleTree::hash(items[3].as_bytes()),
            MerkleTree::hash(items[4].as_bytes()),
        ];

        let tree = MerkleTree::build(&items).unwrap();

        assert_eq!(tree.levels.len(), 4);
        // Check length of each level.
        assert_eq!(tree.levels[0].len(), 5);
        assert_eq!(tree.levels[1].len(), 3);
        assert_eq!(tree.levels[2].len(), 2);
        assert_eq!(tree.levels[3].len(), 1);

        assert_eq!(tree.levels[0], hashes);
        assert_eq!(
            tree.levels[1],
            MerkleTree::merkle_parent_level(&hashes).unwrap()
        );
        assert_eq!(
            tree.levels[2],
            MerkleTree::merkle_parent_level(&tree.levels[1]).unwrap()
        );
        assert_eq!(
            tree.levels[3],
            MerkleTree::merkle_parent_level(&tree.levels[2]).unwrap()
        );
        assert_eq!(tree.root().to_vec(), tree.levels[3][0].to_vec());
    }

    #[test]
    fn test_build_with_no_items_returns_none() {
        let tree = MerkleTree::build(Vec::<&[u8]>::new().as_slice());
        assert!(tree.is_none());
    }

    #[test]
    fn test_proof_of_inclusion_non_existant_hash() {
        let items = vec![
            "and so do all who live to see such times. ",
            "But that is not for them to decide. ",
            "All we have to decide ",
            "is what to do with the time ",
            "that is given us.",
        ];

        let tree = MerkleTree::build(&items).unwrap();

        let non_existant_hash = MerkleTree::hash("Fly, you fools!".as_bytes());

        let proof = tree.proof_of_inclusion(&non_existant_hash);

        assert!(proof.is_none());
    }

    #[test]
    fn test_proof_of_inclusion() {
        let items = vec![
            "and so do all who live to see such times. ",
            "But that is not for them to decide. ",
            "All we have to decide ",
            "is what to do with the time ",
            "that is given us.",
        ];

        let tree = MerkleTree::build(&items).unwrap();

        let hash = MerkleTree::hash(items[2].as_bytes());

        let proof = tree.proof_of_inclusion(&hash).unwrap();

        assert_eq!(proof.len(), 3);
        assert_eq!(proof[0].to_vec(), tree.levels[0][3].to_vec());
        assert_eq!(proof[1].to_vec(), tree.levels[1][0].to_vec());
        assert_eq!(proof[2].to_vec(), tree.levels[2][1].to_vec());
    }

    #[test]
    fn test_validate_wrong_proof() {
        let corrupted_items = vec![
            "and so do all who live to see such times. ",
            "But that is not for them to decide. ",
            "LONG LIVE SAURON ",
            "is what to do with the time ",
            "that is given us.",
        ];

        let corrupt_tree = MerkleTree::build(&corrupted_items).unwrap();
        let corrupt_element_hash = corrupt_tree.levels[0][2];
        let wrong_proof = corrupt_tree
            .proof_of_inclusion(&corrupt_element_hash)
            .unwrap();

        let correct_items = vec![
            "and so do all who live to see such times. ",
            "But that is not for them to decide. ",
            "All we have to decide ",
            "is what to do with the time ",
            "that is given us.",
        ];

        let correct_tree = MerkleTree::build(&correct_items).unwrap();

        assert!(!correct_tree.validate_proof(&corrupt_element_hash, &wrong_proof));
    }

    #[test]
    fn test_validate_correct_proof() {
        let items = vec![
            "and so do all who live to see such times. ",
            "But that is not for them to decide. ",
            "All we have to decide ",
            "is what to do with the time ",
            "that is given us.",
        ];

        let tree = MerkleTree::build(&items).unwrap();

        let hash = MerkleTree::hash(items[2].as_bytes());

        let proof = tree.proof_of_inclusion(&hash).unwrap();

        assert!(tree.validate_proof(&hash, &proof));
    }

    #[test]
    fn test_hash_not_included_returns_false() {
        let items = vec![
            "Home is behind, the world ahead, ",
            "and there are many paths to tread.",
        ];

        let tree = MerkleTree::build(&items).unwrap();

        let hash = MerkleTree::hash("Fly, you fools!".as_bytes());

        assert!(!tree.contains_hash(&hash));
    }

    #[test]
    fn test_hash_included_returns_true() {
        let items = vec![
            "Home is behind, the world ahead, ",
            "and there are many paths to tread.",
        ];

        let tree = MerkleTree::build(&items).unwrap();

        let hash = MerkleTree::hash(items[1].as_bytes());

        assert!(tree.contains_hash(&hash));
    }

    #[test]
    fn test_add_an_element() {
        let items = vec![
            "Learn now the lore of Living Creatures!",
            "First name the four, the free peoples:",
            "Eldest of all, the elf-children;",
            "Dwarf the delver, dark are his houses;",
            "Ent the earthborn, old as mountains;",
        ];

        let mut tree = MerkleTree::build(&items).unwrap();

        assert_eq!(tree.levels[0].len(), 5);

        tree.insert(&"Man the mortal, master of horses:");

        assert_eq!(tree.levels[0].len(), 6);

        let items_complete = vec![
            "Learn now the lore of Living Creatures!",
            "First name the four, the free peoples:",
            "Eldest of all, the elf-children;",
            "Dwarf the delver, dark are his houses;",
            "Ent the earthborn, old as mountains;",
            "Man the mortal, master of horses:",
        ];

        let tree_complete = MerkleTree::build(&items_complete).unwrap();

        assert_eq!(tree.root().to_vec(), tree_complete.root().to_vec());
    }
}
