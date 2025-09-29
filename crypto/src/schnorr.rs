#![allow(non_snake_case)]
use zkp::{self, ark_ec::AffineRepr, toolbox::{prover::Prover, FromBytes, SchnorrCS, ToBytes}, CompactProof, Transcript};

use crate::CryptoError;

/// sign a message using multiple secret keys with Schnorr signature scheme
pub fn sign<G: AffineRepr>(sk: &Vec<G::ScalarField>, Q: &Vec<G>, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sk.len() != Q.len() {
        return Err(CryptoError::SchnorrError("Secret keys and public keys must have the same length".to_string()));
    }
    let mut transcript = Transcript::new(b"SchnorrSignature");
    transcript.append_message(b"msg", msg);
    let mut p: Prover<G, Transcript, _> = Prover::new(b"signature", transcript);
    let (var_G, _) = p.allocate_point(b"G", G::generator());
    for (s, Q) in sk.iter().zip(Q.iter()) {
        let var_s = p.allocate_scalar(b"x", *s);
        
        let (var_Q, _) = p.allocate_point(b"Q", *Q);
        p.constrain(var_Q, vec![(var_s, var_G)]);
    }
    let proof = p.prove_compact();
    let proof = proof.to_bytes()?;
    Ok(proof)
}

/// verify a Schnorr signature for a message using multiple public keys
pub fn verify<G: AffineRepr>(signature: &[u8], Q: &Vec<G>, msg: &[u8]) -> Result<(), CryptoError> {
    let proof = CompactProof::from_bytes(signature)?;
    let mut transcript = Transcript::new(b"SchnorrSignature");
    transcript.append_message(b"msg", msg);
    
    let mut v = zkp::toolbox::verifier::Verifier::<G, Transcript, _>::new(b"signature", transcript);
    let var_G = v.allocate_point(b"G", G::generator())?;
    
    for Q in Q.iter() {
        let var_s = v.allocate_scalar(b"x");
        let var_Q = v.allocate_point(b"Q", *Q)?;
        v.constrain(var_Q, vec![(var_s, var_G)]);
    }
    
    v.verify_compact(&proof).map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cortado::CortadoAffine as G1Affine;
    use cortado::Fr;
    use rand::thread_rng;
    use zkp::ark_ec::CurveGroup;
    use zkp::ark_ff::UniformRand as _;

    #[test]
    fn test_schnorr_signature() {
        let sk: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut thread_rng())).collect();
        let Q: Vec<G1Affine> = sk.iter().map(|s| (G1Affine::generator() * s).into_affine()).collect();
        let msg = b"Hello, Schnorr!";
        
        let signature = sign(&sk, &Q, msg).unwrap();
        assert!(!signature.is_empty());
        
        verify(&signature, &Q, msg).unwrap();
    }
}