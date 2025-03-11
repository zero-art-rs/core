extern crate relative_implementation;

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

    let user_alice = UserIdentity { id: 8u32 };
    let sk_id = ibbe.extract(&user_alice).unwrap();
    println!("sk_id = {:?}\n", sk_id);

    let users_id = vec![1, 8, 4, 5, 3];
    let mut users = Vec::new();
    for user_id in users_id {
        users.push(UserIdentity { id: user_id });
    }

    let (hdr, key) = ibbe.encrypt(&users);
    println!("c1 = {}\n", hdr.c1);
    println!("c2 = {}\n", hdr.c2);
    println!("key = {}\n", key.key);

    let decrypted_key = ibbe.decrypt(&users, &user_alice, &sk_id, &hdr);
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
        ibbe.verify(&message, &sigma, &user_alice)
    );
}

fn measure_time(number_of_iterations: u128) {
    SpeedMetrics::test_complex(10, number_of_iterations);
    SpeedMetrics::test_complex(100, number_of_iterations);
    // SpeedMetrics::test_complex(1000, number_of_iterations);

    SpeedMetrics::test_signature_complex(100, number_of_iterations);
}

fn art_tree_example() {
    let number_of_users = 15u32;
    let ibbe = IBBEDel7::setup(number_of_users);

    let mut users = Vec::new();

    for id in 0..20 {
        users.push(UserIdentity { id });
    }

    let user_index = 5;
    let user = users[user_index].clone();
    let sk_id = ibbe.extract(&user).unwrap();

    let msk = ibbe.msk.clone().expect("Secret key must be set up.");
    let mut art_agent = ARTAgent::setup(Some(msk), ibbe.pk.clone(), user);
    let ciphertexts = art_agent.setup_art(&users);
    // println!("ciphertexts = {:?}\n", ciphertexts);
    println!("computed_key1 = {:?}\n", art_agent.compute_hash());

    let computed_key2 = art_agent.tree_gen(ciphertexts[user_index], sk_id);
    println!("computed_key2 = {:?}\n", computed_key2);

    println!(
        "Keys are equal: {:?}",
        computed_key2.eq(&art_agent.compute_hash())
    );
}

fn main() {
    // example();
    // measure_time(100);
    art_tree_example()
}
