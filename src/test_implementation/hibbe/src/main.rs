extern crate relative_implementation;

use ark_bn254::{
    Bn254, Config, Fq12, Fq12Config, G1Projective as G1, G2Projective as G2, fq::Fq, fq2::Fq2,
    fr::Fr as ScalarField, fr::FrConfig,
};
use ark_std::{One, UniformRand, Zero};
use rand::{Rng, thread_rng};
use relative_implementation::art::ARTRootKey;
use relative_implementation::{
    art::{ART, ARTTrustedAgent, ARTUserAgent},
    hybrid_encryption::HybridEncryption,
    ibbe_del7::{IBBEDel7, UserIdentity},
    schnorr::SchnorrCryptoSystem,
    time_measurements::SpeedMetrics,
    tools,
};
use sha2::Sha512;

fn example() {
    let number_of_users = 15u32;
    let ibbe = IBBEDel7::setup(number_of_users);
    println!("msk = {:?}\n", ibbe.msk);
    println!("pk = {:?}\n", ibbe.pk);

    let users = tools::crete_set_of_identities(15);
    let alice = users.get(0).unwrap();
    let sk_id = ibbe.extract(alice).unwrap();
    println!("sk_id = {:?}\n", sk_id);

    let (hdr, key) = ibbe.encrypt(&users);
    println!("c1 = {}\n", hdr.c1);
    println!("c2 = {}\n", hdr.c2);
    println!("key = {}\n", key.key);

    let decrypted_key = ibbe.decrypt(&users, alice, &sk_id, &hdr);
    println!("decrypted_key = {:?}\n", decrypted_key);

    println!(
        "key == decrypted_key: {:?}\n",
        key.key.eq(&decrypted_key.key)
    );

    let message = String::from("Some string");
    let sigma = ibbe.sign(&message, &sk_id);
    println!("sigma = {:?}", sigma);
    println!(
        "signature verification = {:?}",
        ibbe.verify(&message, &sigma, &alice)
    );
}

fn measure_time(number_of_iterations: u128) {
    SpeedMetrics::test_ibbe(10, number_of_iterations);
    // SpeedMetrics::test_ibbe(100, number_of_iterations);
    // SpeedMetrics::test_ibbe(1000, number_of_iterations);

    SpeedMetrics::test_signature_complex(100, number_of_iterations);

    SpeedMetrics::test_art(10, number_of_iterations);
    // SpeedMetrics::test_art(100, number_of_iterations);
    // SpeedMetrics::test_art(1000, number_of_iterations);

    SpeedMetrics::test_hibbe(100, number_of_iterations);
    // SpeedMetrics::test_hibbe(1000, number_of_iterations);
}

fn art_tree_example() {
    let number_of_users = 15u32;

    let ibbe = IBBEDel7::setup(number_of_users);

    let users = tools::crete_set_of_identities(number_of_users);

    let user_index = thread_rng().gen_range(0..number_of_users) as usize;
    let user = users[user_index].clone();
    let sk_id = ibbe.extract(&user).unwrap();

    let mut art_agent = ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
    let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);
    let mut user_agent =
        ARTUserAgent::new(ART::from_json(&tree.serialise().unwrap()).unwrap(), ciphertexts[user_index], sk_id);
    let root_key = user_agent.root_key;
    println!("computed_key = {:?}", root_key);
}
fn hybrid_example() {
    let number_of_users = 15u32;
    let members = tools::crete_set_of_identities(number_of_users);

    let index1 = 0;
    let index2 = 1;
    let user1 = members.get(index1).unwrap().clone();
    let user2 = members.get(index2).unwrap().clone();

    let ibbe = IBBEDel7::setup(number_of_users);
    let sk_id1 = ibbe.extract(&user1).unwrap();
    let sk_id2 = ibbe.extract(&user2).unwrap();

    let mut art_agent = ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
    let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&members);

    let tree_json = tree.serialise().unwrap();
    let mut user1_agent = ARTUserAgent::new(ART::from_json(&tree_json).unwrap(), ciphertexts[index1], sk_id1);
    let mut user2_agent = ARTUserAgent::new(ART::from_json(&tree_json).unwrap(), ciphertexts[index2], sk_id2);

    let mut hibbe1 = HybridEncryption::new(
        ibbe.clone(),
        user1_agent,
        members.clone(),
        user1.clone(),
        sk_id1,
    );
    let mut hibbe2 = HybridEncryption::new(
        ibbe.clone(),
        user2_agent,
        members.clone(),
        user2.clone(),
        sk_id2,
    );

    let message = String::from("fffcf6c73fc73cf73fc27f83fc");
    let (ciphertext, changes) = hibbe1.encrypt(message);
    let decrypted_message = hibbe2.decrypt(ciphertext.clone(), &changes.clone());
    println!("decrypted_message = {:?}", decrypted_message);
}

fn serialise_example() {
    let number_of_users = 2060;
    let users = tools::crete_set_of_identities(number_of_users);
    let user_index = thread_rng().gen_range(0..number_of_users) as usize;
    let user = users[user_index].clone();

    let ibbe = IBBEDel7::setup(number_of_users);
    let sk_id = ibbe.extract(&user).unwrap();

    let mut art_agent = ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
    let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

    let user_agent = ARTUserAgent::new(ART::from_json(&tree.serialise().unwrap()).unwrap(), ciphertexts[user_index], sk_id);

    // Serialize the struct to a JSON string
    let serialized = tree.serialise().unwrap();
    println!("Serialized: {}", serialized);

    // Deserialize the JSON string back to a struct
    let deserialized = ART::from_json(&serialized).unwrap();
    println!("Deserialized: {:?}", deserialized);
}

fn schnorr_signature_example() {
    let mut rng = thread_rng();
    let system = SchnorrCryptoSystem::new(G1::rand(&mut rng));

    let (sk, pk) = system.key_gen();
    let mut message = "asdgsddsfasdvs".as_bytes().to_vec();
    let signature = system.sign(&message, &sk);
    println!(
        "signature is valid: {}",
        system.verify(&message, &signature, &pk)
    );
    message.append(&mut vec![5]);
    println!(
        "signature is invalid: {}",
        !system.verify(&message, &signature, &pk)
    )
}

fn schnorr_identification_example() {
    let mut rng = thread_rng();
    let system = SchnorrCryptoSystem::new(G1::rand(&mut rng));
    let (sk, pk) = system.key_gen();

    let message = "asdgsddsfasdvs".as_bytes().to_vec();
    let (esk, epk) = system.initialize_interactive_identification_protocol();
    let challenge = system.gen_challenge();
    let mut identity_proof = system.gen_interactive_identity_proof(&challenge, &esk, &epk, &sk);
    println!(
        "identity proof is valid: {}",
        system.verify_interactive_identity_proof(&identity_proof, &pk)
    );
    identity_proof.challenge += challenge;
    println!(
        "identity proof is invalid: {}",
        !system.verify_interactive_identity_proof(&identity_proof, &pk)
    );
}

fn main() {
    // example();
    // art_tree_example();
    // hybrid_example();
    // serialise_example();
    // schnorr_signature_example();
    // schnorr_identification_example();

    measure_time(100);
}
