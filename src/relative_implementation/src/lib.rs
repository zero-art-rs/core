pub mod art;
pub mod ibbe_del7;
pub mod ibbe_del7_time_measurements;
pub mod tools;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::art::ARTAgent;
    use ibbe_del7::{IBBEDel7, UserIdentity};

    #[test]
    fn test_ibbedel7_with_random_values() {
        let number_of_users = 15u32;
        let ibbe = IBBEDel7::setup(number_of_users);

        let user_alice = UserIdentity { id: 8u32 };
        let sk_id = ibbe.extract(&user_alice).unwrap();

        let users_id = vec![1, 8, 4, 5, 3];
        let mut users = Vec::new();
        for user_id in users_id {
            users.push(UserIdentity { id: user_id });
        }

        let (hdr, key) = ibbe.encrypt(&users);

        let decrypted_key = ibbe.decrypt(&users, &user_alice, &sk_id, &hdr);

        // correct encryption
        assert!(key.key.eq(&decrypted_key.key));

        let message = String::from("Some string");
        let sigma = ibbe.sign(&message, &sk_id);

        // correct signature
        assert!(ibbe.verify(&message, &sigma, &user_alice));
    }

    #[test]
    fn test_art_tree_key_computation_with_random_values() {
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

        let computed_key2 = art_agent.tree_gen(ciphertexts[user_index], sk_id);

        assert!(computed_key2.eq(&art_agent.compute_hash()));
    }
}
