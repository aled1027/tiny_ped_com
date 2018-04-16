// -*- mode: rust; -*-
//
// This file is part of tiny-ped-com.
// Copyright (c) 2018 Alex Ledger
// See LICENSE for licensing information.
//
// Authors:
// - Alex Ledger <alex@alexledger.net>
//!
//! A small Rust library for Pedersen commitments over elliptc curves.
//!
//! Example usage:
//!
//! ```
//! let mut rng = OsRng::new().unwrap();
//! let val = tiny_ped_com::CommitmentValue::from_u64(3);
//!
//! let (verifier_pub_key, mut verifier) = tiny_ped_com::CommitVerifier::init(&mut rng);
//! let (commitment, commitment_opening) = tiny_ped_com::Committer::commit(&mut rng, &val, &verifier_pub_key);
//!
//! verifier.receive_commitment(commitment);
//!
//! let did_verify = verifier.verify(&val, &commitment_opening);
//! assert_eq!(did_verify, true);
//! ```
//!
//!

// #![allow(non_snake_case)] // use capital letters for field elements

extern crate curve25519_dalek;
extern crate rand;

use rand::Rng;
use curve25519_dalek::{constants, ristretto::{multiscalar_mul, RistrettoPoint}, scalar::Scalar};

/// The Commitment created by the Committer. Sent to the Verifier so that the committer is bound
/// to some value.
pub struct Commitment(RistrettoPoint);

/// The opening to the commitment. Sent by the committer to the verifier in the
/// third round of communcation to prove that the commitment was for the associated value.
pub struct CommitmentOpening(Scalar);

/// The Verifier's public key. Sent to the Committer is the first round of communication.
#[derive(Clone)]
pub struct VerifierPublicKey(RistrettoPoint);

/// The value that the Committer is comitting to. Must be a valid scalar
/// in the Ristretto field.
pub struct CommitmentValue(Scalar);

/// Committer is the party who is commiting to a value.
pub struct Committer;

/// CommitVerifier is the party who is verifying the commitment.
/// They *send* the first message to the Committer and receive
/// two messages from the sender.
pub struct CommitVerifier {
    pk: VerifierPublicKey,
    commitment: Option<Commitment>,
}

impl CommitmentValue {
    /// Builds a CommitmentValue from a u64. All u64 values are valid scalars.
    pub fn from_u64(x: u64) -> Self {
        CommitmentValue(Scalar::from_u64(x))
    }
}

impl CommitVerifier {
    /// Initialize the Verifier with a random number generator.
    pub fn init<T: Rng>(mut rng: &mut T) -> (VerifierPublicKey, Self) {
        let a = Scalar::random(&mut rng);
        let G = &constants::RISTRETTO_BASEPOINT_POINT;
        let H = a * G;
        let pub_key = VerifierPublicKey(H);
        (
            pub_key.clone(),
            CommitVerifier {
                pk: pub_key,
                commitment: None,
            },
        )
    }

    /// Gives the verifier the commitment received from the Committer.
    pub fn receive_commitment(&mut self, commitment: Commitment) {
        self.commitment = Some(commitment);
    }

    /// Verifies that the received commitment value and commitment opening are valid given the
    /// generated public key from the first round and the received commitment from the second round.
    pub fn verify(&self, val: &CommitmentValue, commitment_opening: &CommitmentOpening) -> bool {
        if let Some(Commitment(C)) = self.commitment {
            let VerifierPublicKey(H) = self.pk;
            let G = &constants::RISTRETTO_BASEPOINT_POINT;
            let &CommitmentOpening(r) = commitment_opening;
            let &CommitmentValue(m) = val;
            let C2 = multiscalar_mul(vec![r, m], vec![G, &H]);
            C == C2
        } else {
            panic!("No commitment received");
        }
    }
}

impl Committer {
    /// Generates the data to commit the Commiter to the provided value.
    pub fn commit<T: Rng>(mut rng: &mut T, val: &CommitmentValue, pk: &VerifierPublicKey)
                          -> (Commitment, CommitmentOpening) {
        let r = Scalar::random(&mut rng);
        let &CommitmentValue(val_as_scalar) = val;
        let G = &constants::RISTRETTO_BASEPOINT_POINT;
        let &VerifierPublicKey(pub_key_point) = pk;
        let C = multiscalar_mul(&[r, val_as_scalar], vec![G, &pub_key_point]);
        (Commitment(C), CommitmentOpening(r))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::OsRng;

    #[test]
    fn good_commitment() {
        let mut rng = OsRng::new().unwrap();
        let val = CommitmentValue::from_u64(3);

        let (verifier_pub_key, mut verifier) = CommitVerifier::init(&mut rng);
        let (commitment, commitment_opening) = Committer::commit(&mut rng, &val, &verifier_pub_key);

        verifier.receive_commitment(commitment);

        let did_verify = verifier.verify(&val, &commitment_opening);
        assert_eq!(did_verify, true);
    }

    #[test]
    fn bad_commitment_opening() {
        let mut rng = OsRng::new().unwrap();
        let val = CommitmentValue::from_u64(3);

        let (verifier_pub_key, mut verifier) = CommitVerifier::init(&mut rng);
        let (commitment, _commitment_opening) = Committer::commit(&mut rng, &val, &verifier_pub_key);

        verifier.receive_commitment(commitment);

        let bad_commitment_opening = CommitmentOpening(Scalar::from_u64(4));
        let did_verify = verifier.verify(&val, &bad_commitment_opening);
        assert_eq!(did_verify, false);
    }


    #[test]
    fn bad_commitment() {
        let mut rng = OsRng::new().unwrap();
        let val = CommitmentValue::from_u64(3);

        let (verifier_pub_key, mut verifier) = CommitVerifier::init(&mut rng);
        let (_commitment, commitment_opening) = Committer::commit(&mut rng, &val, &verifier_pub_key);

        let bad_commitment = Commitment(Scalar::from_u64(2) * constants::RISTRETTO_BASEPOINT_POINT);
        verifier.receive_commitment(bad_commitment);

        let did_verify = verifier.verify(&val, &commitment_opening);
        assert_eq!(did_verify, false);
    }
}

