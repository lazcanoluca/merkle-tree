use merkle_tree::MerkleTree;

fn main() {
    // Create a new Merkle tree from a list of items.
    let items = vec![
        "One Ring to rule them all,",
        "One Ring to find them,",
        "One Ring to bring them all",
        "and in the darkness bind them.",
        "In the Land of Mordor where the Shadows lie.",
    ];

    let merkle_tree = MerkleTree::build(&items).unwrap();

    // Corrupt tree.
    let corrupt_items = vec![
        "One Ring to rule them all,",
        "One Ring to find them,",
        "One Ring to bring them all",
        "and in the darkness bind them.",
        "In the Land of Mordor where the quick brown fox jumps over the lazy dog.",
    ];

    let corrupt_tree = MerkleTree::build(&corrupt_items).unwrap();

    // Generate a proof of inclusion for the corrupt item.
    let corrupt_hash = MerkleTree::hash(corrupt_items[4].as_bytes());

    let corrupt_proof = corrupt_tree.proof_of_inclusion(&corrupt_hash).unwrap();

    // Verify the corrupt proof is invalid.
    assert!(!merkle_tree.validate_proof(&corrupt_hash, &corrupt_proof));

    // Good tree.
    let good_tree = MerkleTree::build(&items).unwrap();

    // Generate a proof of inclusion for the good item.
    let good_hash = MerkleTree::hash(items[4].as_bytes());

    let good_proof = good_tree.proof_of_inclusion(&good_hash).unwrap();

    // Verify the good proof is valid.
    assert!(merkle_tree.validate_proof(&good_hash, &good_proof));
}
