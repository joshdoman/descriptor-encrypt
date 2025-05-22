use anyhow::{anyhow, Result};
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
        Ok(apply_chacha20(payload, encryption_key, nonce))
    }

    fn encrypt_share(
        &self,
        share: Vec<u8>,
        pk: &DescriptorPublicKey,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>> {
        let (nonce, cipher) = get_chacha20_poly1305_cipher(pk, hash, index)?;
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
            let Ok((nonce, cipher)) = get_chacha20_poly1305_cipher(pk, hash, index) else {
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

fn apply_chacha20(
    plaintext: Vec<u8>,
    encryption_key: [u8; 32],
    nonce: [u8; 12],
) -> Vec<u8> {
    let mut cipher = ChaCha20::new(&encryption_key.into(), &nonce.into());
    let mut buffer = plaintext.clone();
    cipher.apply_keystream(&mut buffer);
    buffer
}

fn get_chacha20_poly1305_cipher(
    pk: &DescriptorPublicKey,
    hash: &[u8; 32],
    index: usize,
) -> Result<(chacha20poly1305::Nonce, ChaCha20Poly1305)> {
    let encryption_key = get_encryption_key(pk, hash, index);

    // We can safely use a zero nonce because the key is unique to the ciphertext and index
    let nonce = [0u8; 12];
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
}
