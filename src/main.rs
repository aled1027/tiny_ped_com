#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

extern crate rand;
extern crate curve25519_dalek;

use rand::OsRng;
use curve25519_dalek::{ristretto::{RistrettoPoint, CompressedRistretto, multiscalar_mul},
                       scalar::Scalar,
                       constants};

fn compress(point: RistrettoPoint) -> CompressedRistretto {
    RistrettoPoint::double_and_compress_batch(&vec![point]).pop().unwrap()
}

// TODO: watch their youtube video
// TODO: read docs to make sure that this looks correct, secure, and the fast version
// TODO: double check that a is never used again in protocol
// TODO: make API
// TODO: is this secure randomness?

#[allow(non_snake_case)] // use capital letters for field elements
fn main() {
    let mut rng = OsRng::new().unwrap();
    let m = Scalar::from_u64(3);

    let G = &constants::RISTRETTO_BASEPOINT_POINT;

    // Evaluator: (given G)
    let a = Scalar::random(&mut rng);
    let H = a * G;

    // Committer: (Given m, G, H)
    let r = Scalar::random(&mut rng);
    let C = multiscalar_mul(vec![r, m], vec![G, &H]);

    // Committer commits by sending C to evaluator
    // Commiter later decommits by sending (m, r) to evaluator

    // Evaluator checks: (Given r, m, G, H, C)
    let C2 = multiscalar_mul(vec![r, m], vec![G, &H]);

    let does_pass = C == C2;

    println!("Does pass: {}", does_pass);
    println!("Hello, world!");
}

