use anyhow::{Result, anyhow};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use miniscript::descriptor::{DescriptorPublicKey, SinglePubKey};
use sha2::{Digest, Sha256};

/// A trait to construct a cipher
pub trait KeyCipher {
    /// Returns an encrypted payload
    fn encrypt_payload(
        &self,
        payload: Vec<u8>,
        encryption_key: [u8; 32],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>>;

    /// Returns a decrypted payload
    fn decrypt_payload(
        &self,
        encrypted_payload: Vec<u8>,
        encryption_key: [u8; 32],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>>;

    /// Returns a share encrypted using a public key, a derivation hash, and an index
    fn encrypt_share(
        &self,
        share: Vec<u8>,
        pk: &DescriptorPublicKey,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>>;

    /// Returns plaintext decrypted using a set of public keys, a derivation hash, and an index
    fn decrypt_share(
        &self,
        encrypted_share: Vec<u8>,
        pks: &Vec<Option<&DescriptorPublicKey>>,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>>;
}

pub struct AuthenticatedCipher {}

pub struct UnauthenticatedCipher {}

impl KeyCipher for AuthenticatedCipher {
    fn encrypt_payload(
        &self,
        payload: Vec<u8>,
        encryption_key: [u8; 32],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>> {
        Ok(apply_chacha20(payload, encryption_key, nonce))
    }

    fn decrypt_payload(
        &self,
        encrypted_payload: Vec<u8>,
        encryption_key: [u8; 32],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>> {
        Ok(apply_chacha20(encrypted_payload, encryption_key, nonce))
    }

    fn encrypt_share(
        &self,
        share: Vec<u8>,
        pk: &DescriptorPublicKey,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>> {
        let encryption_key = get_encryption_key(pk, hash, index);
        // We can safely use a zero nonce because the key is unique to the ciphertext and index
        let nonce = [0u8; 12];
        let (nonce, cipher) = get_chacha20_poly1305_cipher(encryption_key, nonce)?;
        let encrypted_share = cipher
            .encrypt(&nonce, share.as_ref())
            .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 encryption error: {:?}", e))?;

        Ok(encrypted_share.as_slice().try_into().unwrap())
    }

    fn decrypt_share(
        &self,
        encrypted_share: Vec<u8>,
        pks: &Vec<Option<&DescriptorPublicKey>>,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>> {
        for pk in pks {
            let Some(pk) = pk else {
                continue;
            };
            let encryption_key = get_encryption_key(pk, hash, index);
            let nonce = [0u8; 12];
            let Ok((nonce, cipher)) = get_chacha20_poly1305_cipher(encryption_key, nonce) else {
                continue;
            };
            let Ok(share) = cipher.decrypt(&nonce, encrypted_share.as_ref()) else {
                continue;
            };

            return Ok(share);
        }

        Err(anyhow!("Failed to decrypt"))
    }
}

impl KeyCipher for UnauthenticatedCipher {
    fn encrypt_payload(
        &self,
        payload: Vec<u8>,
        encryption_key: [u8; 32],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>> {
        let (nonce, cipher) = get_chacha20_poly1305_cipher(encryption_key, nonce)?;
        let encrypted_payload = cipher
            .encrypt(&nonce, payload.as_ref())
            .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 encryption error: {:?}", e))?;

        Ok(encrypted_payload.as_slice().try_into().unwrap())
    }

    fn decrypt_payload(
        &self,
        encrypted_payload: Vec<u8>,
        encryption_key: [u8; 32],
        nonce: [u8; 12],
    ) -> Result<Vec<u8>> {
        let (nonce, cipher) = get_chacha20_poly1305_cipher(encryption_key, nonce)?;
        cipher
            .decrypt(&nonce, encrypted_payload.as_ref())
            .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 decryption error: {:?}", e))
    }

    fn encrypt_share(
        &self,
        share: Vec<u8>,
        pk: &DescriptorPublicKey,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>> {
        let encryption_key = get_encryption_key(pk, hash, index);
        let nonce = [0u8; 12];

        Ok(apply_chacha20(share, encryption_key, nonce))
    }

    fn decrypt_share(
        &self,
        encrypted_share: Vec<u8>,
        pks: &Vec<Option<&DescriptorPublicKey>>,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>> {
        if index >= pks.len() {
            return Err(anyhow!("Insufficient keys for index {}", index));
        }

        let Some(pk) = pks[index] else {
            return Err(anyhow!("No key exists at index {}", index));
        };

        let encryption_key = get_encryption_key(pk, hash, index);
        let nonce = [0u8; 12];

        Ok(apply_chacha20(encrypted_share, encryption_key, nonce))
    }
}

fn apply_chacha20(plaintext: Vec<u8>, encryption_key: [u8; 32], nonce: [u8; 12]) -> Vec<u8> {
    let mut cipher = ChaCha20::new(&encryption_key.into(), &nonce.into());
    let mut buffer = plaintext.clone();
    cipher.apply_keystream(&mut buffer);
    buffer
}

fn get_chacha20_poly1305_cipher(
    encryption_key: [u8; 32],
    nonce: [u8; 12],
) -> Result<(chacha20poly1305::Nonce, ChaCha20Poly1305)> {
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
        .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 key error: {:?}", e))?;

    Ok((*nonce, cipher))
}

fn get_encryption_key(pk: &DescriptorPublicKey, hash: &[u8; 32], leaf_index: usize) -> [u8; 32] {
    let mut key_material = match pk {
        DescriptorPublicKey::Single(single_pub) => match single_pub.key {
            SinglePubKey::FullKey(full_pk) => full_pk.inner.serialize().to_vec(),
            SinglePubKey::XOnly(xpk) => xpk.serialize().to_vec(),
        },
        DescriptorPublicKey::XPub(xkey) => xkey.xkey.encode().to_vec(),
        DescriptorPublicKey::MultiXPub(multi_xkey) => multi_xkey.xkey.encode().to_vec(),
    };
    key_material.extend(hash.clone());
    key_material.extend(leaf_index.to_le_bytes().to_vec());

    let mut hasher = Sha256::new();
    hasher.update(key_material);
    let encryption_key = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(encryption_key.as_slice());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        PublicKey,
        secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey},
    };
    use miniscript::descriptor::SinglePub;

    // Helper function to create a DescriptorPublicKey for testing
    fn create_test_pk(seed_val: u32) -> DescriptorPublicKey {
        let secp = Secp256k1::new();
        let mut sk_bytes = [0u8; 32];
        sk_bytes[0..4].copy_from_slice(&seed_val.to_be_bytes());

        let secret_key = SecretKey::from_slice(&sk_bytes)
            .unwrap_or_else(|_| panic!("Failed to create secret key from seed {}", seed_val));

        let pk_inner = SecpPublicKey::from_secret_key(&secp, &secret_key);

        let full_pk = PublicKey {
            inner: pk_inner,
            compressed: true,
        };

        DescriptorPublicKey::Single(SinglePub {
            key: SinglePubKey::FullKey(full_pk),
            origin: None,
        })
    }

    // Helper function to create a dummy 32-byte hash
    fn create_dummy_hash(seed: u8) -> [u8; 32] {
        let mut seed_data = [0u8; 32];
        seed_data[0] = seed;
        Sha256::digest(&seed_data).into()
    }

    #[test]
    fn test_encrypt_decrypt_cycle_succeeds() {
        let cipher = AuthenticatedCipher {};
        let pk = create_test_pk(1);
        let hash = create_dummy_hash(1);
        let index = 0_usize;
        let plaintext = b"this is a secret message".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index)
            .unwrap();

        let decrypted_plaintext = cipher.decrypt_share(ciphertext, &vec![Some(&pk)], &hash, index);

        assert_eq!(
            decrypted_plaintext.unwrap(),
            plaintext,
            "Decrypted plaintext should match original."
        );
    }

    #[test]
    fn test_decrypt_with_wrong_public_key_fails() {
        let cipher = AuthenticatedCipher {};
        let pk1 = create_test_pk(1);
        let pk2 = create_test_pk(2);
        let hash = create_dummy_hash(1);
        let index = 0_usize;
        let plaintext = b"another secret".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk1, &hash, index)
            .unwrap();

        let decrypted_plaintext = cipher.decrypt_share(ciphertext, &vec![Some(&pk2)], &hash, index);

        assert!(
            decrypted_plaintext.is_err(),
            "Decryption should fail with the wrong public key."
        );
    }

    #[test]
    fn test_decrypt_with_wrong_hash_fails() {
        let cipher = AuthenticatedCipher {};
        let pk = create_test_pk(1);
        let hash1 = create_dummy_hash(1);
        let hash2 = create_dummy_hash(2);
        let index = 0_usize;
        let plaintext = b"secret with hash".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash1, index)
            .unwrap();

        let decrypted_plaintext = cipher.decrypt_share(ciphertext, &vec![Some(&pk)], &hash2, index);

        assert!(
            decrypted_plaintext.is_err(),
            "Decryption should fail with the wrong hash."
        );
    }

    #[test]
    fn test_decrypt_with_wrong_index_fails() {
        let cipher = AuthenticatedCipher {};
        let pk = create_test_pk(1);
        let hash = create_dummy_hash(1);
        let index1 = 0_usize;
        let index2 = 1_usize;
        let plaintext = b"secret with index".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index1)
            .unwrap();

        let decrypted_plaintext = cipher.decrypt_share(ciphertext, &vec![Some(&pk)], &hash, index2);

        assert!(
            decrypted_plaintext.is_err(),
            "Decryption should fail with the wrong index."
        );
    }

    #[test]
    fn test_decrypt_with_list_of_pks_correct_key_present_succeeds() {
        let cipher = AuthenticatedCipher {};
        let pk_correct = create_test_pk(10);
        let pk_wrong1 = create_test_pk(11);
        let pk_wrong2 = create_test_pk(12);
        let hash = create_dummy_hash(5);
        let index = 3_usize;
        let plaintext = b"find the right key!".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk_correct, &hash, index)
            .unwrap();

        let pks_list = vec![Some(&pk_wrong1), Some(&pk_correct), Some(&pk_wrong2)];
        let decrypted_plaintext = cipher.decrypt_share(ciphertext, &pks_list, &hash, index);

        assert_eq!(
            decrypted_plaintext.unwrap(),
            plaintext,
            "Decryption should succeed if the correct key is in the list."
        );
    }

    #[test]
    fn test_decrypt_with_list_of_pks_correct_key_absent_fails() {
        let cipher = AuthenticatedCipher {};
        let pk_correct = create_test_pk(20);
        let pk_wrong1 = create_test_pk(21);
        let pk_wrong2 = create_test_pk(22);
        let hash = create_dummy_hash(6);
        let index = 4_usize;
        let plaintext = b"key not here".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk_correct, &hash, index)
            .unwrap();

        let pks_list = vec![Some(&pk_wrong1), Some(&pk_wrong2)];
        let decrypted_plaintext = cipher.decrypt_share(ciphertext, &pks_list, &hash, index);

        assert!(
            decrypted_plaintext.is_err(),
            "Decryption should fail if the correct key is not in the list."
        );
    }

    #[test]
    fn test_empty_plaintext_encrypt_decrypt_succeeds() {
        let cipher = AuthenticatedCipher {};
        let pk = create_test_pk(30);
        let hash = create_dummy_hash(7);
        let index = 5_usize;
        let plaintext = Vec::new();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index)
            .unwrap();

        let decrypted_plaintext = cipher.decrypt_share(ciphertext, &vec![Some(&pk)], &hash, index);

        assert_eq!(
            decrypted_plaintext.unwrap(),
            plaintext,
            "Encryption/decryption of empty plaintext should work."
        );
    }

    #[test]
    fn test_decrypt_with_empty_pk_list_fails() {
        let cipher = AuthenticatedCipher {};
        let pk_correct = create_test_pk(40);
        let hash = create_dummy_hash(8);
        let index = 6_usize;
        let plaintext = b"no keys to try".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk_correct, &hash, index)
            .unwrap();

        let pks_list_empty = Vec::new();
        let decrypted_plaintext = cipher.decrypt_share(ciphertext, &pks_list_empty, &hash, index);

        assert!(
            decrypted_plaintext.is_err(),
            "Decryption should fail if the list of public keys is empty."
        );
    }

    #[test]
    fn test_different_pks_produce_different_ciphertexts() {
        let cipher = AuthenticatedCipher {};
        let pk1 = create_test_pk(51);
        let pk2 = create_test_pk(52);
        let hash = create_dummy_hash(9);
        let index = 7_usize;
        let plaintext = b"same data, different key".to_vec();

        let ciphertext1 = cipher
            .encrypt_share(plaintext.clone(), &pk1, &hash, index)
            .unwrap();
        let ciphertext2 = cipher
            .encrypt_share(plaintext.clone(), &pk2, &hash, index)
            .unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Ciphertexts should differ if public keys differ."
        );
    }

    #[test]
    fn test_different_hashes_produce_different_ciphertexts() {
        let cipher = AuthenticatedCipher {};
        let pk = create_test_pk(60);
        let hash1 = create_dummy_hash(10);
        let hash2 = create_dummy_hash(11);
        let index = 8_usize;
        let plaintext = b"same data, different hash".to_vec();

        let ciphertext1 = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash1, index)
            .unwrap();
        let ciphertext2 = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash2, index)
            .unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Ciphertexts should differ if hashes differ."
        );
    }

    #[test]
    fn test_different_indices_produce_different_ciphertexts() {
        let cipher = AuthenticatedCipher {};
        let pk = create_test_pk(70);
        let hash = create_dummy_hash(12);
        let index1 = 9_usize;
        let index2 = 10_usize;
        let plaintext = b"same data, different index".to_vec();

        let ciphertext1 = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index1)
            .unwrap();
        let ciphertext2 = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index2)
            .unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Ciphertexts should differ if indices differ."
        );
    }

    // UnauthenticatedCipher Tests

    #[test]
    fn test_encrypt_decrypt_cycle_succeeds_unauthenticated() {
        let cipher = UnauthenticatedCipher {};
        let pk = create_test_pk(101);
        let hash = create_dummy_hash(101);
        let index = 0_usize;
        let plaintext = b"unauth secret message".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index)
            .unwrap();

        let decrypted_plaintext = cipher
            .decrypt_share(ciphertext, &vec![Some(&pk)], &hash, index)
            .unwrap();

        assert_eq!(
            decrypted_plaintext, plaintext,
            "Unauthenticated decrypted plaintext should match original."
        );
    }

    #[test]
    fn test_decrypt_unauthenticated_with_wrong_public_key_at_index_garbles() {
        let cipher = UnauthenticatedCipher {};
        let pk1_enc = create_test_pk(102);
        let pk2_dec = create_test_pk(103);
        let hash = create_dummy_hash(102);
        let index = 0_usize;
        let plaintext = b"unauth wrong pk".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk1_enc, &hash, index)
            .unwrap();

        let decrypted_plaintext = cipher
            .decrypt_share(ciphertext, &vec![Some(&pk2_dec)], &hash, index)
            .unwrap();

        assert_ne!(
            decrypted_plaintext, plaintext,
            "Unauthenticated decryption with wrong PK at index should produce different data."
        );
    }

    #[test]
    fn test_decrypt_unauthenticated_with_wrong_hash_garbles() {
        let cipher = UnauthenticatedCipher {};
        let pk = create_test_pk(104);
        let hash1_enc = create_dummy_hash(103);
        let hash2_dec = create_dummy_hash(104);
        let index = 0_usize;
        let plaintext = b"unauth wrong hash".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash1_enc, index)
            .unwrap();

        let decrypted_plaintext = cipher
            .decrypt_share(ciphertext, &vec![Some(&pk)], &hash2_dec, index)
            .unwrap();

        assert_ne!(
            decrypted_plaintext, plaintext,
            "Unauthenticated decryption with wrong hash should produce different data."
        );
    }

    #[test]
    fn test_decrypt_unauthenticated_with_wrong_index_param_garbles() {
        let cipher = UnauthenticatedCipher {};
        let pk = create_test_pk(105);
        let hash = create_dummy_hash(105);
        let index1_enc = 0_usize;
        let index2_dec = 1_usize;
        let plaintext = b"unauth wrong index param".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index1_enc)
            .unwrap();

        let pks_for_decryption = if index2_dec == 0 {
            vec![Some(&pk)]
        } else {
            vec![None, Some(&pk)]
        };

        let decrypted_plaintext = cipher
            .decrypt_share(ciphertext, &pks_for_decryption, &hash, index2_dec)
            .unwrap();

        assert_ne!(
            decrypted_plaintext, plaintext,
            "Unauthenticated decryption with wrong index parameter should produce different data."
        );
    }

    #[test]
    fn test_decrypt_unauthenticated_with_correct_pk_at_specified_index_succeeds() {
        let cipher = UnauthenticatedCipher {};
        let pk_correct = create_test_pk(110);
        let pk_other = create_test_pk(111);
        let hash = create_dummy_hash(110);
        let encrypt_idx = 1_usize;
        let decrypt_idx = 1_usize;
        let plaintext = b"unauth correct pk at index".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk_correct, &hash, encrypt_idx)
            .unwrap();

        let pks_list = vec![Some(&pk_other), Some(&pk_correct), Some(&pk_other)];
        let decrypted_plaintext = cipher
            .decrypt_share(ciphertext, &pks_list, &hash, decrypt_idx)
            .unwrap();

        assert_eq!(
            decrypted_plaintext, plaintext,
            "Unauthenticated decryption should succeed if correct PK is at specified index."
        );
    }

    #[test]
    fn test_decrypt_unauthenticated_with_wrong_pk_at_specified_index_garbles() {
        let cipher = UnauthenticatedCipher {};
        let pk_encrypt = create_test_pk(112);
        let pk_decrypt_wrong = create_test_pk(113);
        let pk_other = create_test_pk(114);
        let hash = create_dummy_hash(111);
        let encrypt_idx = 0_usize;
        let decrypt_idx = 0_usize;
        let plaintext = b"unauth wrong pk at index".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk_encrypt, &hash, encrypt_idx)
            .unwrap();

        let pks_list = vec![Some(&pk_decrypt_wrong), Some(&pk_other)];
        let decrypted_plaintext = cipher
            .decrypt_share(ciphertext, &pks_list, &hash, decrypt_idx)
            .unwrap();

        assert_ne!(
            decrypted_plaintext, plaintext,
            "Unauthenticated decryption with wrong PK at specified index should garble."
        );
    }

    #[test]
    fn test_empty_plaintext_encrypt_decrypt_succeeds_unauthenticated() {
        let cipher = UnauthenticatedCipher {};
        let pk = create_test_pk(130);
        let hash = create_dummy_hash(130);
        let index = 0_usize;
        let plaintext = Vec::new();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index)
            .unwrap();

        let decrypted_plaintext = cipher
            .decrypt_share(ciphertext, &vec![Some(&pk)], &hash, index)
            .unwrap();

        assert_eq!(
            decrypted_plaintext, plaintext,
            "Unauthenticated encryption/decryption of empty plaintext should work."
        );
    }

    #[test]
    fn test_decrypt_unauthenticated_with_empty_pk_list_fails() {
        let cipher = UnauthenticatedCipher {};
        let pk_correct = create_test_pk(140);
        let hash = create_dummy_hash(140);
        let index_enc = 0_usize;
        let index_dec = 0_usize;
        let plaintext = b"unauth no keys".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk_correct, &hash, index_enc)
            .unwrap();

        let pks_list_empty: Vec<Option<&DescriptorPublicKey>> = Vec::new();
        let result = cipher.decrypt_share(ciphertext, &pks_list_empty, &hash, index_dec);

        assert!(
            result.is_err(),
            "Unauthenticated decryption should fail if PK list is empty and index is accessed."
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("Insufficient keys for index {}", index_dec)
        );
    }

    #[test]
    fn test_decrypt_unauthenticated_with_out_of_bounds_index_fails() {
        let cipher = UnauthenticatedCipher {};
        let pk = create_test_pk(141);
        let hash = create_dummy_hash(141);
        let index_enc = 0_usize;
        let index_dec = 1_usize;
        let plaintext = b"unauth out of bounds".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index_enc)
            .unwrap();

        let pks_list = vec![Some(&pk)];
        let result = cipher.decrypt_share(ciphertext, &pks_list, &hash, index_dec);

        assert!(
            result.is_err(),
            "Unauthenticated decryption should fail for out-of-bounds index."
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("Insufficient keys for index {}", index_dec)
        );
    }

    #[test]
    fn test_decrypt_unauthenticated_with_none_pk_at_index_fails() {
        let cipher = UnauthenticatedCipher {};
        let pk_enc = create_test_pk(142);
        let hash = create_dummy_hash(142);
        let index_enc = 0_usize;
        let index_dec = 0_usize;
        let plaintext = b"unauth none pk".to_vec();

        let ciphertext = cipher
            .encrypt_share(plaintext.clone(), &pk_enc, &hash, index_enc)
            .unwrap();

        let pks_list = vec![None];
        let result = cipher.decrypt_share(ciphertext, &pks_list, &hash, index_dec);

        assert!(
            result.is_err(),
            "Unauthenticated decryption should fail if PK at index is None."
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            format!("No key exists at index {}", index_dec)
        );
    }

    #[test]
    fn test_different_pks_produce_different_ciphertexts_unauthenticated() {
        let cipher = UnauthenticatedCipher {};
        let pk1 = create_test_pk(151);
        let pk2 = create_test_pk(152);
        let hash = create_dummy_hash(150);
        let index = 0_usize;
        let plaintext = b"unauth same data, diff key".to_vec();

        let ciphertext1 = cipher
            .encrypt_share(plaintext.clone(), &pk1, &hash, index)
            .unwrap();
        let ciphertext2 = cipher
            .encrypt_share(plaintext.clone(), &pk2, &hash, index)
            .unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Unauthenticated ciphertexts should differ if public keys differ."
        );
    }

    #[test]
    fn test_different_hashes_produce_different_ciphertexts_unauthenticated() {
        let cipher = UnauthenticatedCipher {};
        let pk = create_test_pk(160);
        let hash1 = create_dummy_hash(160);
        let hash2 = create_dummy_hash(161);
        let index = 0_usize;
        let plaintext = b"unauth same data, diff hash".to_vec();

        let ciphertext1 = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash1, index)
            .unwrap();
        let ciphertext2 = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash2, index)
            .unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Unauthenticated ciphertexts should differ if hashes differ."
        );
    }

    #[test]
    fn test_different_indices_produce_different_ciphertexts_unauthenticated() {
        let cipher = UnauthenticatedCipher {};
        let pk = create_test_pk(170);
        let hash = create_dummy_hash(170);
        let index1 = 0_usize;
        let index2 = 1_usize;
        let plaintext = b"unauth same data, diff index".to_vec();

        let ciphertext1 = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index1)
            .unwrap();
        let ciphertext2 = cipher
            .encrypt_share(plaintext.clone(), &pk, &hash, index2)
            .unwrap();

        assert_ne!(
            ciphertext1, ciphertext2,
            "Unauthenticated ciphertexts should differ if indices differ."
        );
    }
}
