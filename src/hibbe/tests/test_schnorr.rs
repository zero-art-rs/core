#[cfg(test)]
mod tests {
    use ark_bn254::{fr::Fr as ScalarField, G1Projective as G1, G2Projective as G2};
    use ark_ff::One;
    use ark_std::UniformRand;
    use hibbe::schnorr::SchnorrCryptoSystem;
    use rand::thread_rng;
    use sha2::{Digest, Sha512};

    #[test]
    fn schnorr_signature() {
        let mut rng = thread_rng();
        let system = SchnorrCryptoSystem::new(G1::rand(&mut rng));

        let (sk, pk) = system.key_gen();
        let mut message = "asdgsddsfasdvs".as_bytes().to_vec();
        let signature = system.sign(&message, &sk);
        assert!(system.verify(&message, &signature, &pk));

        let other_message = "dsfsdffsd".as_bytes().to_vec();
        assert!(
            !system.verify(&other_message, &signature, &pk),
            "Signature can work for different messages"
        );
    }

    #[test]
    fn schnorr_identification() {
        let mut rng = thread_rng();
        let system = SchnorrCryptoSystem::new(G1::rand(&mut rng));
        let (sk, pk) = system.key_gen();

        let message = "asdgsddsfasdvs".as_bytes().to_vec();
        let (esk, epk) = system.initialize_interactive_identification_protocol();
        let challenge = system.gen_challenge();
        let mut identity_proof = system.gen_interactive_identity_proof(&challenge, &esk, &epk, &sk);

        assert!(system.verify_interactive_identity_proof(&identity_proof, &pk));

        identity_proof.challenge += challenge;
        assert!(
            !system.verify_interactive_identity_proof(&identity_proof, &pk),
            "Accepted wrong identity poof"
        );
    }

    #[test]
    fn schnorr_non_interactive_identification() {
        let mut rng = thread_rng();
        let system = SchnorrCryptoSystem::new(G1::rand(&mut rng));
        let (sk, pk) = system.key_gen();

        let message = "asdgsddsfasdvs".as_bytes().to_vec();
        let mut identity_proof = system.gen_non_interactive_identity_proof(&sk, &pk);

        assert!(system.verify_non_interactive_identity_proof(&identity_proof, &pk));

        identity_proof.challenge += ScalarField::one();
        assert!(
            !system.verify_non_interactive_identity_proof(&identity_proof, &pk),
            "Accepted while challenge in proof is wrong"
        );
    }
}
