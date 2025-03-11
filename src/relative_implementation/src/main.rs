extern crate relative_implementation;

use rand::{Rng, thread_rng};
use relative_implementation::art::ARTAgent;
use relative_implementation::tools;
use relative_implementation::{
    ibbe_del7::{IBBEDel7, UserIdentity},
    ibbe_del7_time_measurements::SpeedMetrics,
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
    let (tree, ciphertexts) = art_agent.compute_art_and_ciphertexts(&users);
    let root_key = tree.root_key.unwrap().key;
    println!("computed_key = {:?}", root_key);

    let computed_root_key2 = tree.compute_key(ciphertexts[user_index], sk_id, &ibbe.pk);
    println!("computed_root_key = {:?}", computed_root_key2);

    println!("Keys are equal: {:?}", computed_root_key2.eq(&root_key));
}

fn main() {
    example();
    art_tree_example();

    // measure_time(100);
}
