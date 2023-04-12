#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_snake_case)]

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

use sha2::{Sha256, Digest};
use hex;



#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatenating
    hashes: Vec<(HashDirection, &'a Hash)>,
}

/*Sha2 hash single Vec<u8> data to yield Vec<u8;32>*/
fn hash_data(data: &Data) -> Hash {
    Sha256::digest(data).to_vec()
}

/*iteratively concats two hash strings*/
fn hash_concat(h1: &Hash, h2: &Hash) -> Hash {
    let h3 = h1.iter().chain(h2).copied().collect();
    hash_data(&h3)
}

#[derive(Debug)]
struct MerkleTree {
    /*nodes in the merkle tree*/
    nodes: Vec<Vec<u8>>,
    /*the number of layers */
    layer: usize,
}

impl MerkleTree {

    /*the function to construct the Merkle tree*/
    pub fn construct(input: &[Data]) -> MerkleTree {
        /*iterativelly hashes all the given inputs.*/
        let mut hashes: Vec<Vec<Hash>> = vec![input.iter().map(hash_data).collect()];
        /*initiate from the bottom layer of tree*/
        let mut tree_root = &hashes[0];
        /*calculate the number of layers in the tree*/
        let layer_num = (input.len() as f64).log2() as usize; 

        /*iterate over the layer*/
        for _ in 0..layer_num {

            let mut one_layer = vec![tree_root.chunks(2) /*get the nodes as the twin pairs*/
            .map(|x| hash_concat(&x[0], &x[1])) /*combine and hash two nodes*/
            .collect()]; 
            hashes.append(&mut one_layer); /*append the yielded layer*/
            /*get the root of the tree; top node index is 
            (number_of_node - 1) due to index initiate at zero*/
            tree_root = &hashes[hashes.len() - 1]; 
        }

        /*records the outcomes as MerkleTree structure*/
        MerkleTree {
            nodes: hashes.into_iter().flatten().collect(),
            layer: layer_num + 1,
        }
    }

    /*
    access MerkleTree's nodes to retrieve the tree's root.
    consequently, compares it with the given `root_hash`.
    @return true the hash is equals, or otherwise.
    */
    pub fn verify(&self, input: &[Data], root_hash: &Hash) -> bool {
       self.nodes[self.nodes.len() - 1] == *root_hash
    }

    /*obtain the nodes in trees based on the index of
    data for the proof validation*/
    pub fn prove(&self, data: &Data) -> Option<Proof> {
        let data_hash = hash_data(data); /*hash the data*/
        let idx = self
            .nodes[0..2_usize.pow((self.layer - 1) as u32)] /*walkthrough the tree*/
            .iter()
            .position(|leaf| *leaf == data_hash)?; /*obtain the position of the data on tree*/

        let mut proof = Proof::default();
        let mut known_location = idx;
    
        for _ in 0..self.layer - 1 {
            // We already know (or already can compute) the hash of one side of
            // the pair, so just need to return the other for the proof
            let required_hash = if known_location % 2 == 0 { /*if the index is even*/
                (HashDirection::Right, &self.nodes[known_location + 1]) /*that means its sibling is on right*/
            } else {
                (HashDirection::Left, &self.nodes[known_location - 1]) /*else get the sibling on left*/
            };
    
            proof.hashes.push(required_hash); /*records the relevant nodes*/
    
            // Now we are able to calculate hash of the parent, so the parent of
            // this node is now the known node
            known_location = self.nodes.len() - ((self.nodes.len() - known_location) / 2);
        }

        Some(proof)
    }

    /*validate the tree*/
    pub fn verify_proof(&self, data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let mut current_hash = hash_data(data); /**/

        /*iterate over the sibling nodes*/
        for (hash_direction, hash) in proof.hashes.iter() {
            current_hash = match hash_direction {
                HashDirection::Left => hash_concat(hash, &current_hash),/*if current hash is at left, concat the hash at right*/
                HashDirection::Right => hash_concat(&current_hash, hash), /*if current hash is at right, concat the*/
            };
        }
    
        current_hash == *root_hash
    }
}

fn example_data(n: usize) -> Vec<Data> {
    let mut data = vec![];
    for i in 0..n {
        data.push(vec![i as u8]);
    }
    data
}

fn main() {
    let data = example_data(8);
    println!("{:?}", &data);
    let tree = MerkleTree::construct(&data);
    println!("{:?}", &tree);
    let sample = vec![2];
    let prove = tree.prove(&sample).unwrap();
    println!("{:?}", &prove);
    println!("root: {:?}", &tree.nodes[&tree.nodes.len() - 1]);
    let validity = tree.verify_proof(&sample, &prove, &tree.nodes[&tree.nodes.len() - 1]);
    println!("{:?}", &validity);
}

#[cfg(tests)]
    use super::*;

    #[test]
    fn test_constructions() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        let root_hash = hex::encode(&tree.nodes[&tree.nodes.len() - 1]);
        assert_eq!(&root_hash, expected_root);

       


        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        let root_hash = hex::encode(&tree.nodes[&tree.nodes.len() - 1]);
        assert_eq!(&root_hash, expected_root);

        
    }
    
