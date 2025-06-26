use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use art::{ART, PrivateART};
use std::ops::Mul;
use zk::curve::cortado::{
    self, CortadoAffine, Fq as BaseField, Fr as ScalarField, FromScalar, ToScalar,
};
use zk::art::{random_witness_gen, art_prove, art_verify};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use zkp::toolbox::cross_dleq::{CrossDLEQProof, CrossDleqProver, CrossDleqVerifier, PedersenBasis};
use zkp::toolbox::dalek_ark::{ark_to_ristretto255, ristretto255_to_ark, scalar_to_ark};
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use rand::{rng, Rng};



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
    let (art, tk) = PrivateART::new_art_from_secrets(&secrets, &generator);

    // This art can be converted to string using serde serialise as serde_json::to_string(&art)
    // or using build in method.

    let string_representation = art.to_string().unwrap();
    let recovered_art =
        PrivateART::<CortadoAffine>::from_string_and_secret_key(&string_representation, &secrets[0])
            .unwrap();

    assert_eq!(recovered_art.art, art.art);

    // Assume art_i is i-th user art. i-th user knows i-th secret key
    let mut art_0 =
        PrivateART::<CortadoAffine>::from_string_and_secret_key(&string_representation, &secrets[0])
            .unwrap();
    let mut art_1 =
        PrivateART::<CortadoAffine>::from_string_and_secret_key(&string_representation, &secrets[1])
            .unwrap();
    let new_secret_key_1 = ScalarField::rand(&mut rng);
    // Every user will update his leaf secret key after receival.
    let (tk_1, changes_1) = art_1.update_key(&new_secret_key_1).unwrap();

    // Root key tk is a new common secret. Other users can use returned changes to update theirs trees.
    art_0.update_art(&changes_1).unwrap();
    // Now, to get common secret, usr can call the next
    let tk_0 = art_0.recompute_root_key().unwrap();

    assert_eq!(tk_0.key, tk_1.key);

    // Users can further modify art as next.
    // Upend new node for new member.
    let some_secret_key1 = ScalarField::rand(&mut rng);
    let (_, changes_2) = art_1.append_node(&some_secret_key1).unwrap();
    // Update secret key
    let some_secret_key2 = ScalarField::rand(&mut rng);
    let (_, changes_3) = art_1.update_key(&some_secret_key2).unwrap();
    // Upend new node for new member.
    let some_secret_key3 = ScalarField::rand(&mut rng);
    let (_, changes_4) = art_1.append_node(&some_secret_key3).unwrap();
    // Remove member from the tree, by making his node temporal.
    let public_key = generator.mul(&some_secret_key3).into_affine();
    let (tk_1, changes_5) = art_1
        .make_node_temporal(&public_key, &some_secret_key2)
        .unwrap();

    // Other users will update their trees correspondingly.
    art_0.update_art(&changes_2).unwrap();
    art_0.update_art(&changes_3).unwrap();
    art_0.update_art(&changes_4).unwrap();
    art_0.update_art(&changes_5).unwrap();
    let tk_0 = art_0.recompute_root_key().unwrap();

    assert_eq!(tk_0.key, tk_1.key);

    // For proof generation. there might be useful the next method.
    let (tk, co_path, lambdas) = art_1.recompute_root_key_with_artefacts().unwrap();

    let k = co_path.len();
    
    let g_1 = CortadoAffine::generator();
    let h_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

    let gens = PedersenGens::default();
    let basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
        g_1,
        h_1,
        ristretto255_to_ark(gens.B).unwrap(),
        ristretto255_to_ark(gens.B_blinding).unwrap(),
    );
    
    let s = (0..2).map(|_| cortado::Fr::rand(&mut rng)).collect::<Vec<_>>();
    let blindings: Vec<Scalar> = (0..k+1).map(|_| Scalar::random(&mut rng)).collect();
    
    let proof = art_prove(
        &BulletproofGens::new(2048, 1),
        basis.clone(),
        co_path.clone(),
        lambdas.clone(),
        s,
        blindings
    ).unwrap();
    
    let verification_result = art_verify(
        &BulletproofGens::new(2048, 1),
        basis,
        co_path,
        proof
    );
    
    assert!(verification_result.is_ok());
}

/// Usage example for usual ART
fn public_example() {
    let number_of_users = 100;
    let generator = CortadoAffine::generator();
    let mut rng = StdRng::seed_from_u64(rand::random());

    // To create a new tree, the creator of a group will firstly create a set of invitations.
    // Those invitations contain leaf secret keys, which are scalars for the scalar field of the
    // curve. Note, that the first secret in a set, must be a creators secret key, because the
    // owner of group is defined as a left most node in a tree.
    let secrets = (0..number_of_users)
        .map(|_| ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();

    // For new art, creator provides the next method with set of secrets and some generator.
    let (art, tk) = ART::new_art_from_secrets(&secrets, &generator);

    // This art can be converted to string using serde serialise as serde_json::to_string(&art)
    // or using build in method.

    let string_representation = art.to_string().unwrap();
    let recovered_art = ART::from_string(&string_representation).unwrap();

    assert_eq!(recovered_art, art);

    // Assume art_i is i-th user art. i-th user knows i-th secret key
    let mut art_0 = art.clone();
    let mut art_1 = art.clone();
    let new_secret_key_1 = ScalarField::rand(&mut rng);
    // Every user will update his leaf secret key after receival.
    let (tk_1, changes_1) = art_1.update_key(&secrets[0], &new_secret_key_1).unwrap();

    // Root key tk is a new common secret. Other users can use returned changes to update theirs trees.
    art_0.update_art(&changes_1).unwrap();
    // Now, to get common secret, usr can call the next
    let tk_0 = art_0.recompute_root_key(new_secret_key_1).unwrap();

    assert_eq!(tk_0.key, tk_1.key);

    // Users can further modify art as next.
    // Upend new node for new member.
    let some_secret_key1 = ScalarField::rand(&mut rng);
    let (_, changes_2) = art_1.append_node(&some_secret_key1).unwrap();
    // Update secret key
    let some_secret_key2 = ScalarField::rand(&mut rng);
    let (_, changes_3) = art_1.update_key(&secrets[1], &some_secret_key2).unwrap();
    // Upend new node for new member.
    let some_secret_key3 = ScalarField::rand(&mut rng);
    let (_, changes_4) = art_1.append_node(&some_secret_key3).unwrap();
    // Remove member from the tree, by making his node temporal.
    let public_key = generator.mul(&some_secret_key3).into_affine();
    let (tk_1, changes_5) = art_1
        .make_node_temporal(&public_key, &some_secret_key2)
        .unwrap();

    // Other users will update their trees correspondingly.
    art_0.update_art(&changes_2).unwrap();
    art_0.update_art(&changes_3).unwrap();
    art_0.update_art(&changes_4).unwrap();
    art_0.update_art(&changes_5).unwrap();
    let tk_0 = art_0.recompute_root_key(new_secret_key_1).unwrap();

    assert_eq!(tk_0.key, tk_1.key);
}

fn main() {
    public_example();
    private_example();
}
