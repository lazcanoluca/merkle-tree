# Merkle Tree

This project is a Rust implementation of a Merkle Tree.

## Usage

To use this crate, include it as a dependency in your `Cargo.toml` file.

```toml
[dependencies]
merkle-tree = { git = "https://github.com/lazcanoluca/merkle-tree.git" }
```

Then, import and use:

### Creation and insertion of elements

```rust
use merkle_tree::MerkleTree;

fn main() {
    // Create a new Merkle tree from a list of items.
    let items = vec!["In a hole in the ground", "there lived a hobbit."];

    let mut merkle_tree = MerkleTree::build(&items).unwrap();

    // Get the root hash of the Merkle tree.
    let root = merkle_tree.root();

    println!("Root: {:?}", root);

    // Add an item to the Merkle tree.
    let new_item = "The quick brown fox jumps over the lazy dog.";

    merkle_tree.insert(&new_item);

    // Get the new root hash of the Merkle tree.
    let new_root = merkle_tree.root();

    println!("New root: {:?}", new_root);
}
```

### Creation and verification of proofs

```rust
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
```


## Tests

Just clone and `cargo test`.

## Features

- [x] A Merkle Tree can be built out of an array.

- [x] A Merkle Tree can generate a proof that it contains an element.

- [x] A Merkle Tree can validate that the proof for a given hash is correct.

- [x] A Merkle Tree can verify that a given hash is contained in it.

- [x] A Merke Tree can be dynamic, this means that elements can be added once it is built.
