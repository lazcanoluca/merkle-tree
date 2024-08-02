use merkle_tree::MerkleTree;

fn main() {
    // Create a new Merkle tree from a list of items.
    let items = vec!["In a hole in the ground", "there lived a hobbit."];

    let mut merkle_tree = MerkleTree::build(&items).unwrap();

    // Get the root hash of the Merkle tree.
    let root = merkle_tree.root();

    println!("Root: {:?}", root);

    // Add an item to the Merkle tree.
    merkle_tree.insert(&"Gandalf the Grey");

    // Get the new root hash of the Merkle tree.
    let new_root = merkle_tree.root();

    println!("New root: {:?}", new_root);
}
