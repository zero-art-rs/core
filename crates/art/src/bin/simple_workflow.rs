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
use cortado::{self, CortadoAffine, Fr as ScalarField};
use curve25519_dalek::scalar::Scalar;
use std::ops::Mul;
use zk::art::{art_prove, art_verify};
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ristretto255_to_ark;

/// PrivateART usage example. PrivateART contain handle key management, while ART isn't.
fn private_example() {
    let number_of_users = 100;
    let generator = CortadoAffine::generator();
    let mut rng = StdRng::seed_from_u64(rand::random());

    // To create a new tree, the creator of a group will create a set of invitations.
    // Those invitations contain leaf secret keys, which are elements of curve scalar field.
    // Note, that the first secret in a set, must be a creators secret key, because the
    // owner of group is defined as a left most node in a tree.
    let secrets: Vec<ScalarField> = (0..number_of_users)
        .map(|_| ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();

    // For new art, creator provides the next method with set of secrets and some generator.
    let (art, _) = PrivateART::new_art_from_secrets(&secrets, &generator).unwrap();

    // This art can be converted to string using serde serialize as serde_json::to_string(&art)
    // or using build in method.

    let encoded_representation = art.serialize().unwrap();
    let recovered_art =
        PrivateART::<CortadoAffine>::deserialize(&encoded_representation, &secrets[0]).unwrap();

    assert_eq!(recovered_art.root, art.root);

    // Assume art_i is i-th user art. i-th user knows i-th secret key
    let mut art_0 =
        PrivateART::<CortadoAffine>::deserialize(&encoded_representation, &secrets[0]).unwrap();
    let mut art_1 =
        PrivateART::<CortadoAffine>::deserialize(&encoded_representation, &secrets[1]).unwrap();
    let new_secret_key_1 = ScalarField::rand(&mut rng);
    // Every user will update his leaf secret key after receival.
    let (tk_1, changes_1, _) = art_1.update_key(&new_secret_key_1).unwrap();

    // Root key tk is a new common secret. Other users can use returned changes to update theirs trees.
    art_0.update_public_art(&changes_1).unwrap();
    // Now, to get common secret, usr can call the next
    let tk_0 = art_0.recompute_root_key().unwrap();

    assert_eq!(tk_0.key, tk_1.key);

    // Users can further modify art as next.
    // Upend new node for new member.
    let some_secret_key1 = ScalarField::rand(&mut rng);
    let (_, changes_2, artefacts_2) = art_1.append_or_replace_node_in_public_art(&some_secret_key1).unwrap();
    // Update secret key
    let some_secret_key2 = ScalarField::rand(&mut rng);
    let (_, changes_3, artefacts_3) = art_1.update_key(&some_secret_key2).unwrap();
    // Upend new node for new member.
    let some_secret_key3 = ScalarField::rand(&mut rng);
    let (_, changes_4, artefacts_4) = art_1.append_or_replace_node_in_public_art(&some_secret_key3).unwrap();
    // Remove member from the tree, by making his node temporary.
    let public_key = generator.mul(&some_secret_key3).into_affine();
    let (tk_1, changes_5, artefacts_5) = art_1
        .make_blank_in_public_art(&art_1.get_path_to_leaf(&public_key).unwrap(), &some_secret_key2)
        .unwrap();

    // Other users will update their trees correspondingly.
    art_0.update_public_art(&changes_2).unwrap();
    art_0.update_public_art(&changes_3).unwrap();
    art_0.update_public_art(&changes_4).unwrap();
    art_0.update_public_art(&changes_5).unwrap();
    let tk_0 = art_0.recompute_root_key().unwrap();

    assert_eq!(tk_0.key, tk_1.key);

    // For proof generation, there might be useful the next method.
    let (_, artefacts) = art_1.get_root_key_with_artefacts().unwrap();
    assert_eq!(artefacts.path, artefacts_4.path);
    assert_eq!(artefacts.co_path, artefacts_4.co_path);
    assert_eq!(artefacts.secrets, artefacts_4.secrets);

    let k = artefacts.co_path.len();

    let g_1 = CortadoAffine::generator();
    let h_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

    let gens = PedersenGens::default();
    let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
        g_1,
        h_1,
        ristretto255_to_ark(gens.B).unwrap(),
        ristretto255_to_ark(gens.B_blinding).unwrap(),
    );

    let aux_keys = (0..2)
        .map(|_| cortado::Fr::rand(&mut rng))
        .collect::<Vec<_>>();
    let public_aux_keys = aux_keys
        .iter()
        .map(|sk| CortadoAffine::generator().mul(sk).into_affine())
        .collect::<Vec<_>>();
    let blinding_vector: Vec<Scalar> = (0..k + 1).map(|_| Scalar::random(&mut rng)).collect();
    let associated_data = vec![0x72, 0x75, 0x73, 0x73, 0x69, 0x61, 0x64, 0x69, 0x65];

    let proof = art_prove(
        basis.clone(),
        &associated_data,
        public_aux_keys.clone(),
        artefacts.path.clone(),
        artefacts.co_path.clone(),
        artefacts.secrets.clone(),
        aux_keys.clone(),
        blinding_vector,
    )
    .unwrap();

    let verification_result = art_verify(
        basis,
        &associated_data,
        public_aux_keys.clone(),
        artefacts.path.clone(),
        artefacts.co_path.clone(),
        proof,
    );

    assert!(verification_result.is_ok());
}

fn main() {
    private_example();
}
