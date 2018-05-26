# Tiny Ped Com

A small Rust library for Pedersen commitments over elliptic curves.

Pedersen commitments are a cryptographic construction for allowing a party, Alice, to commit to a value to another party, Bob, without revealing the value to Bob until later. Alice can later _open_ the commitment by telling Bob the value she committed to along with a _proof_ that her value now is the same as her value before.

This implementation uses [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) for elliptic curve operations.

## Example

```
let mut rng = OsRng::new().unwrap();
let val = tiny_ped_com::CommitmentValue::from_u64(3);

let (verifier_pub_key, mut verifier) = tiny_ped_com::CommitVerifier::init(&mut rng);
let (commitment, commitment_opening) = tiny_ped_com::Committer::commit(&mut rng, &val, &verifier_pub_key);

verifier.receive_commitment(commitment);

let did_verify = verifier.verify(&val, &commitment_opening);
assert_eq!(did_verify, true);
```

## Warnings

Use at your own risk. This cryptography code is un-audited and extremely likely to have security bugs. It is not recommended for use of any kind.
