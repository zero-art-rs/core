extern crate relative_implementation;

use relative_implementation::ibbe_del7::IBBEDel7;
use relative_implementation::ibbe_del7_time_measurements::SpeedMetrics;

fn example() {
    let number_of_users = 15u32;
    let (msk, pk) = IBBEDel7::run_setup(number_of_users);
    println!("msk = {:?}\n", msk);
    println!("pk = {:?}\n", pk);

    let user_id = 8u32;
    let sk_id = IBBEDel7::extract(&msk, user_id);
    println!("sk_id = {:?}\n", sk_id);

    let users_set = vec![1, 8, 4, 5, 3];

    let (hdr, key) = IBBEDel7::encrypt(&users_set, &pk);
    println!("c1 = {}\n", hdr.0);
    println!("c2 = {}\n", hdr.1);
    println!("key = {key}\n");

    let decrypted_key = IBBEDel7::decrypt(&users_set, user_id, &sk_id, &hdr, &pk);
    println!("decrypted_key = {decrypted_key}\n");

    println!("key == decrypted_key: {}\n", key.eq(&decrypted_key));
}

fn main() {
    // example();
    SpeedMetrics::test_all(100);
}
