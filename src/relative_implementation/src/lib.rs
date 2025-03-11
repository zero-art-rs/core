pub mod art;
pub mod hybrid_encryption;
pub mod ibbe_del7;
pub mod ibbe_del7_time_measurements;
pub mod tools;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        art::ARTAgent,
        ibbe_del7::{IBBEDel7, UserIdentity},
        tools,
    };

    #[test]
    fn test_ibbedel7_with_random_values() {
        let number_of_users = 15u32;
        let ibbe = IBBEDel7::setup(number_of_users);

        let users = tools::crete_set_of_identities(number_of_users);
        let alice = users.get(0).unwrap();
        let sk_id = ibbe.extract(&alice).unwrap();

        let (hdr, key) = ibbe.encrypt(&users);

        let decrypted_key = ibbe.decrypt(&users, &alice, &sk_id, &hdr);

        // correct encryption
        assert!(key.key.eq(&decrypted_key.key));

        let message = String::from("Some string");
        let sigma = ibbe.sign(&message, &sk_id);

        // correct signature
        assert!(ibbe.verify(&message, &sigma, &alice));
    }

    #[test]
    fn test_art_tree_key_computation_with_random_values() {
        let number_of_users = 15u32;
        let ibbe = IBBEDel7::setup(number_of_users);

        let mut users = tools::crete_set_of_identities(number_of_users);

        let user_index = 5;
        let user = users[user_index].clone();
        let sk_id = ibbe.extract(&user).unwrap();

        let msk = ibbe.msk.clone().expect("Secret key must be set up.");
        let mut art_agent = ARTAgent::new(msk, ibbe.pk.clone());
        let (tree, ciphertexts) = art_agent.compute_art_and_ciphertexts(&users);

        let computed_root_key = tree.compute_key(ciphertexts[user_index], sk_id, &ibbe.pk);

        assert!(computed_root_key.eq(&tree.root_key.unwrap().key));
    }
}
