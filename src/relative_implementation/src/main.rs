extern crate relative_implementation;

use rand::{Rng, thread_rng};
use relative_implementation::{
    art::ARTAgent,
    hybrid_encryption::HybridEncryption,
    ibbe_del7::{IBBEDel7, UserIdentity},
    ibbe_del7_time_measurements::SpeedMetrics,
    tools,
};

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
    SpeedMetrics::test_complex::<String>(10, number_of_iterations);
    SpeedMetrics::test_complex::<String>(100, number_of_iterations);
    // SpeedMetrics::test_complex(1000, number_of_iterations);

    SpeedMetrics::test_signature_complex::<String>(100, number_of_iterations);

    SpeedMetrics::test_art_agent::<String>(10, number_of_iterations);
    SpeedMetrics::test_art_agent::<String>(100, number_of_iterations);
    // SpeedMetrics::test_art_agent::<String>(1000, number_of_iterations);
}

fn art_tree_example() {
    let number_of_users = 15u32;

    let ibbe = IBBEDel7::setup(number_of_users);

    let users = tools::crete_set_of_identities(number_of_users);

    let user_index = thread_rng().gen_range(0..number_of_users) as usize;
    let user = users[user_index].clone();
    let sk_id = ibbe.extract(&user).unwrap();

    let mut art_agent = ARTAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
    let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);
    let root_key = tree.root_key.unwrap();
    println!("computed_key = {:?}", root_key);

    let computed_root_key2 = tree.compute_key(ciphertexts[user_index], sk_id, &ibbe.pk.get_h());
    println!("computed_root_key = {:?}", computed_root_key2);

    println!(
        "Keys are equal: {:?}",
        computed_root_key2.key.eq(&root_key.key)
    );
}
fn hybrid_example() {
    let number_of_users = 15u32;
    let users = tools::crete_set_of_identities(number_of_users);

    let index1 = 0;
    let index2 = 1;
    let user1 = users.get(index1).unwrap().clone();
    let user2 = users.get(index2).unwrap().clone();

    let ibbe = IBBEDel7::setup(number_of_users);
    let sk_id1 = ibbe.extract(&user1).unwrap();
    let sk_id2 = ibbe.extract(&user2).unwrap();

    let mut art_agent = ARTAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
    let (mut tree1, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);
    let root_key = tree1.compute_key(ciphertexts[index1], sk_id1, &ibbe.pk.get_h());

    let mut tree2 = art_agent.recompute_tree(&users);
    tree2.compute_key(ciphertexts[index2], sk_id2, &ibbe.pk.get_h());

    let mut hibbe1 =
        HybridEncryption::new(ibbe.clone(), tree1, users.clone(), user1.clone(), sk_id1);
    let mut hibbe2 =
        HybridEncryption::new(ibbe.clone(), tree2, users.clone(), user2.clone(), sk_id2);

    let message = String::from(
        "Some string for encryption to see if it is really working, because I have some doubts about it.",
    );
    let (ciphertext, changes) = hibbe1.encrypt(message);

    let decrypted_message = hibbe2.decrypt(ciphertext.clone(), &changes.clone());
    println!("decrypted_message = {:?}", decrypted_message);
    // let decrypted_message = hibbe2.decrypt(ciphertext.clone(), &changes.clone());
    // println!("decrypted_message = {:?}", decrypted_message);
}

fn main() {
    // example();
    // art_tree_example();
    hybrid_example();

    // measure_time(100);
}
