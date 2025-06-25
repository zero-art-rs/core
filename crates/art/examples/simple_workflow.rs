use ark_ec::PrimeGroup;
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use art::ART;
use std::ops::Mul;
use zk::curve::cortado::{CortadoProjective as ARTG, Fr as ScalarField};

fn main() {
    let number_of_users = 100;
    let generator = ARTG::generator();
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
    let public_key = generator.mul(&some_secret_key3);
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
