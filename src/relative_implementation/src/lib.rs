pub mod art;
pub mod hybrid_encryption;
pub mod ibbe_del7;
pub mod ibbe_del7_time_measurements;
pub mod tools;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_encryption::HybridEncryption;
    use crate::{
        art::ARTAgent,
        ibbe_del7::{IBBEDel7, UserIdentity},
        tools,
    };
    use ark_ec::pairing::Pairing;
    use rand::{Rng, thread_rng};

    #[test]
    fn test_ibbedel7_with_random_values() {
        let number_of_users = 15u32;
        let ibbe = IBBEDel7::setup(number_of_users);

        let users = tools::crete_set_of_identities(number_of_users);
        let alice_id = thread_rng().gen_range(0..number_of_users as usize);
        let alice = users.get(alice_id).unwrap();
        let sk_id = ibbe.extract(&alice).unwrap();

        let (hdr, key) = ibbe.encrypt(&users);

        let decrypted_key = ibbe.decrypt(&users, &alice, &sk_id, &hdr);

        // correct encryption
        assert_eq!(key.key, decrypted_key.key);

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

        let alice_id = thread_rng().gen_range(0..number_of_users as usize);
        let user = users[alice_id].clone();
        let sk_id = ibbe.extract(&user).unwrap();

        let msk = ibbe.msk.clone().expect("Secret key must be set up.");
        let mut art_agent = ARTAgent::new(msk, ibbe.pk.clone());
        let (mut tree, ciphertexts, root_tree) = art_agent.compute_art_and_ciphertexts(&users);

        let computed_root_key =
            tree.compute_root_key(ciphertexts[alice_id], sk_id, &ibbe.pk.get_h());

        assert_eq!(computed_root_key.key, root_tree.key);
    }

    #[test]
    fn test_art_tree_update() {
        let number_of_users = 15u32;
        let ibbe = IBBEDel7::setup(number_of_users);

        let mut users = tools::crete_set_of_identities(number_of_users);

        let user_id = thread_rng().gen_range(0..number_of_users as usize);
        let user = users[user_id].clone();
        let sk_id = ibbe.extract(&user).unwrap();

        let msk = ibbe.msk.clone().expect("Secret key must be set up.");
        let mut art_agent = ARTAgent::new(msk, ibbe.pk.clone());
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let computed_root_key =
            tree.compute_root_key(ciphertexts[user_id], sk_id, &ibbe.pk.get_h());

        // Assert trusted party and users computed the same tree key. Skip lambda because trusted party cant compute it
        assert_eq!(computed_root_key.key, root_key.key);

        let (new_key, _) = tree.update_key().unwrap();

        // Assert tree.update_key() changes key and lambda
        assert_ne!(computed_root_key.key, new_key.key);
        assert_ne!(computed_root_key.lambda, new_key.lambda);

        let (old_updated_key, _) = tree
            .change_lambda(computed_root_key.lambda.unwrap())
            .unwrap();

        // Assert, that change of lambdas: lambda1 -> lambda2 -> lambda1, gives the same values
        assert_eq!(computed_root_key.lambda, old_updated_key.lambda);
        assert_eq!(computed_root_key.key, old_updated_key.key);
    }

    #[test]
    fn test_art_update_from_two_users() {
        let number_of_users = 20u32;
        let users = tools::crete_set_of_identities(number_of_users);

        let index1 = thread_rng().gen_range(0..number_of_users as usize);
        let mut index2 = index1;
        while index2 == index1 {
            index2 = thread_rng().gen_range(0..number_of_users as usize);
        }

        let user1 = users.get(index1).unwrap().clone();
        let user2 = users.get(index2).unwrap().clone();

        let ibbe = IBBEDel7::setup(number_of_users);
        let sk_id1 = ibbe.extract(&user1).unwrap();
        let sk_id2 = ibbe.extract(&user2).unwrap();

        let mut art_agent = ARTAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);
        let root_key1 = tree.compute_root_key(ciphertexts[index1], sk_id1, &ibbe.pk.get_h());

        let mut tree_copy = art_agent.get_recomputed_art();
        let root_key2 = tree_copy.compute_root_key(ciphertexts[index2], sk_id2, &ibbe.pk.get_h());

        assert_eq!(root_key1.key, root_key2.key);
        assert_ne!(root_key1.lambda, root_key2.lambda);
    }

    #[test]
    fn test_art_update_branch() {
        let number_of_users = 20;
        let users = tools::crete_set_of_identities(number_of_users);

        let index1 = thread_rng().gen_range(0..number_of_users as usize);
        let mut index2 = index1;
        while index2 == index1 {
            index2 = thread_rng().gen_range(0..number_of_users as usize);
        }

        let user1 = users.get(index1).unwrap().clone();
        let user2 = users.get(index2).unwrap().clone();

        let ibbe = IBBEDel7::setup(number_of_users);
        let sk_id1 = ibbe.extract(&user1).unwrap();
        let sk_id2 = ibbe.extract(&user2).unwrap();

        let mut art_agent = ARTAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
        let (mut tree1, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let mut tree1 = art_agent.get_recomputed_art();
        tree1.remove_root_key();
        tree1.compute_root_key(ciphertexts[index1], sk_id1, &ibbe.pk.get_h());

        let mut tree2 = art_agent.get_recomputed_art();
        tree2.remove_root_key();
        tree2.compute_root_key(ciphertexts[index2], sk_id2, &ibbe.pk.get_h());

        assert_eq!(tree1.root_key.unwrap().key, tree2.root_key.unwrap().key);
        assert_ne!(
            tree1.root_key.unwrap().lambda,
            tree2.root_key.unwrap().lambda
        );

        let (key, changes) = tree1.update_key().unwrap();
        _ = tree2.update_branch(&changes);

        assert_eq!(tree1.root_key.unwrap().key, tree2.root_key.unwrap().key);
        assert_ne!(
            tree1.root_key.unwrap().lambda,
            tree2.root_key.unwrap().lambda
        );
    }

    #[test]
    fn test_hibbe_encryption() {
        let number_of_users = 20u32;
        let users = tools::crete_set_of_identities(number_of_users);

        let index1 = thread_rng().gen_range(0..number_of_users as usize);
        let mut index2 = index1;
        while index2 == index1 {
            index2 = thread_rng().gen_range(0..number_of_users as usize);
        }

        let user1 = users.get(index1).unwrap().clone();
        let user2 = users.get(index2).unwrap().clone();

        let ibbe = IBBEDel7::setup(number_of_users);
        let sk_id1 = ibbe.extract(&user1).unwrap();
        let sk_id2 = ibbe.extract(&user2).unwrap();

        let mut art_agent = ARTAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
        let (mut tree1, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);
        let root_key = tree1.compute_root_key(ciphertexts[index1], sk_id1, &ibbe.pk.get_h());

        let mut tree1 = art_agent.get_recomputed_art();
        tree1.remove_root_key();
        tree1.compute_root_key(ciphertexts[index1], sk_id1, &ibbe.pk.get_h());

        let mut tree2 = art_agent.get_recomputed_art();
        tree2.remove_root_key();
        tree2.compute_root_key(ciphertexts[index2], sk_id2, &ibbe.pk.get_h());

        let mut hibbe1 =
            HybridEncryption::new(ibbe.clone(), tree1, users.clone(), user1.clone(), sk_id1);
        let mut hibbe2 =
            HybridEncryption::new(ibbe.clone(), tree2, users.clone(), user2.clone(), sk_id2);

        let message = String::from(
            "Some string for encryption to see if it is really working, because I have some doubts about it.",
        );
        let (ciphertext, changes) = hibbe1.encrypt(message.clone());
        let decrypted_message = hibbe2.decrypt(ciphertext.clone(), &changes.clone());
        // Assert the second user can decrypt the message
        assert_eq!(message, decrypted_message);

        let message2 = String::from(
            "Some string2 for encryption to see if it is really working, because I have some doubts about it.",
        );
        let (ciphertext2, changes2) = hibbe2.encrypt(message2.clone());
        let decrypted_message2 = hibbe1.decrypt(ciphertext2.clone(), &changes2.clone());
        // Assert users can have a conversation
        assert_eq!(message2, decrypted_message2);
    }
}
