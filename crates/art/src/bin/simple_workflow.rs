use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use art::{
    traits::{ARTPrivateAPI, ARTPublicAPI},
    types::PrivateART,
};
use bulletproofs::PedersenGens;
use cortado::{ALT_GENERATOR_X, ALT_GENERATOR_Y, CortadoAffine, Fr};
use curve25519_dalek::scalar::Scalar;
use std::ops::Mul;
use zk::art::{art_prove, art_verify};
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ristretto255_to_ark;

/// PrivateART usage example. PrivateART contain handle key management, while ART isn't.
fn general_example() {
    let number_of_users = 8;
    let generator = CortadoAffine::generator();
    let mut rng = StdRng::seed_from_u64(rand::random());

    // To create a new tree, the creator of a group will create a set of invitations.
    // Those invitations contain leaf secret keys, which are elements of curve scalar field.
    // Note, that the first secret in a set, must be a creators secret key, because the
    // owner of group is defined as a left most node in a tree.
    let secrets: Vec<Fr> = (0..number_of_users)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    // For new art, creator provides the next method with set of secrets and some generator.
    let (art, _) = PrivateART::new_art_from_secrets(&secrets, &generator).unwrap();

    // PrivateART implements Serialize and Deserialize, however there is a default implementation
    // for serialization with postcard. It will return bytes for serialized PublicART, which
    // doesn't contain any secret keys.
    let encoded_representation = art.serialize().unwrap();
    // The deserialization method requires leaf secret key, as the encoded_representation is
    // the encoding of PrivateART.
    let recovered_art =
        PrivateART::<CortadoAffine>::deserialize(&encoded_representation, &secrets[0]).unwrap();

    assert_eq!(recovered_art, art);

    // Assume art_i is i-th user art, which also knows i-th secret key.
    let mut art_0 =
        PrivateART::<CortadoAffine>::deserialize(&encoded_representation, &secrets[0]).unwrap();
    let mut art_1 =
        PrivateART::<CortadoAffine>::deserialize(&encoded_representation, &secrets[1]).unwrap();
    let new_secret_key_1 = Fr::rand(&mut rng);

    // Any user can update his public art with the next method.
    let (tk_1, change_1, _) = art_1.update_key(&new_secret_key_1).unwrap();
    // Root key tk is a new common secret. Other users can use returned change to update
    // theirs trees. Fot example, it can be done as next:
    art_0.update_private_art(&change_1).unwrap();
    assert_eq!(art_0, art_1);

    // To get common secret, user can call the next method
    let retrieved_tk_1 = art_0.get_root_key().unwrap();
    assert_eq!(retrieved_tk_1, tk_1);

    // Other art modifications include addition and blanking.
    // Addition of a new node can be done as next:
    let new_node1_secret_key = Fr::rand(&mut rng);
    let (_, changes_2, _) = art_1
        .append_or_replace_node(&new_node1_secret_key)
        .unwrap();
    art_0.update_private_art(&changes_2).unwrap();
    assert_eq!(art_0, art_1);

    // Remove member from the tree, by making his node temporary.
    let new_node1_public_key = generator.mul(&new_node1_secret_key).into_affine();
    let some_secret_key1 = Fr::rand(&mut rng);
    let (tk_3, changes_3, _) = art_1
        .make_blank(
            &art_1.get_path_to_leaf(&new_node1_public_key).unwrap(),
            &some_secret_key1,
        )
        .unwrap();
    art_0.update_private_art(&changes_3).unwrap();
    assert_eq!(art_0, art_1);

    // For proof generation, use `ProverArtefacts` structure. They are returned with every art update.
    // Lets prove key update:
    let some_secret_key4 = Fr::rand(&mut rng);
    let (_, changes_4, prover_artefacts) = art_1
        .update_key(&some_secret_key4).unwrap();

    let k = prover_artefacts.co_path.len();

    // Generate pedersen basis
    let g_1 = CortadoAffine::generator();
    let h_1 = CortadoAffine::new_unchecked(ALT_GENERATOR_X, ALT_GENERATOR_Y);

    let gens = PedersenGens::default();
    let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
        g_1,
        h_1,
        ristretto255_to_ark(gens.B).unwrap(),
        ristretto255_to_ark(gens.B_blinding).unwrap(),
    );

    // Append auxiliary keys to proof, for example old root key or old leaf key
    let aux_keys = vec![tk_3.key];
    let public_aux_keys = aux_keys
        .iter()
        .map(|sk| CortadoAffine::generator().mul(sk).into_affine())
        .collect::<Vec<_>>();
    // Generate blinding vector
    let blinding_vector: Vec<Scalar> = (0..k + 1).map(|_| Scalar::random(&mut rng)).collect();
    // Pass some associated data
    let associated_data = b"associated data".to_vec();

    let proof = art_prove(
        basis.clone(),
        &associated_data,
        public_aux_keys.clone(),
        prover_artefacts.path.clone(),
        prover_artefacts.co_path.clone(),
        prover_artefacts.secrets.clone(),
        aux_keys.clone(),
        blinding_vector,
    )
    .unwrap();

    // To verify the proof one need to have only part of artefacts stored in VerifierArtefacts plus changes
    let verifier_artefacts = art_1.compute_artefacts_for_verification(&changes_4).unwrap();

    let verification_result = art_verify(
        basis,
        &associated_data,
        public_aux_keys.clone(),
        verifier_artefacts.path.clone(),
        verifier_artefacts.co_path.clone(),
        proof,
    );

    assert!(verification_result.is_ok());
}

fn merge_conflict_changes() {
    let mut rng = &mut StdRng::seed_from_u64(0);
    let secrets: Vec<Fr> = (0..100)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let (art0, _) =
        PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

    // Serialise and deserialize art for the other users.
    let public_art_bytes = art0.serialize().unwrap();

    // Store the basic art1.
    let art1: PrivateART<CortadoAffine> =
        PrivateART::deserialize(&public_art_bytes, &secrets[1]).unwrap();

    // Create new users arts
    let mut user0: PrivateART<CortadoAffine> =
        PrivateART::deserialize(&public_art_bytes, &secrets[0]).unwrap();

    let mut user2: PrivateART<CortadoAffine> =
        PrivateART::deserialize(&public_art_bytes, &secrets[2]).unwrap();

    let mut user3: PrivateART<CortadoAffine> =
        PrivateART::deserialize(&public_art_bytes, &secrets[8]).unwrap();

    let mut user4: PrivateART<CortadoAffine> =
        PrivateART::deserialize(&public_art_bytes, &secrets[10]).unwrap();

    let mut user5: PrivateART<CortadoAffine> =
        PrivateART::deserialize(&public_art_bytes, &secrets[67]).unwrap();


    let sk0 = Fr::rand(&mut rng);
    let (_, change0, _) = user0.update_key(&sk0).unwrap();

    let sk2 = Fr::rand(&mut rng);
    let (_, change2, _) = user2.update_key(&sk2).unwrap();

    let sk3 = Fr::rand(&mut rng);
    let (_, change3, _) = user3.update_key(&sk3).unwrap();

    let applied_change = vec![change0.clone()];
    let all_but_0_changes = vec![change2.clone(), change3.clone()];
    let all_changes = vec![change0, change2, change3];

    // Merge for users which participated in the merge
    let mut participant = user0.clone();
    participant.recompute_path_secrets_for_participant(&all_but_0_changes, &art0.clone()).unwrap();
    participant.merge_with_skip(&applied_change, &all_but_0_changes).unwrap();

    // Merge for users which only observed the merge conflict
    let mut observer = art1.clone();
    observer.recompute_path_secrets_for_observer(&all_changes).unwrap();
    observer.merge(&all_changes).unwrap();

    assert_eq!(
        participant,
        observer,
        "Observer and participant have the same wiev on the state of the art."
    );
}

fn main() {
    general_example();
    merge_conflict_changes();
}
