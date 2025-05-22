// SPDX-License-Identifier: CC0-1.0

use anyhow::{Result, anyhow, ensure};
use itertools::Itertools;
use miniscript::{
    Threshold,
    descriptor::{Descriptor, DescriptorPublicKey},
};
use sha2::{Digest, Sha256};

use super::cipher::{AuthenticatedCipher, KeyCipher, UnauthenticatedCipher};
use super::descriptor_tree::{KeylessDescriptorTree, ToDescriptorTree};
use super::shamir::{Share, reconstruct_secret, split_secret};

type Data = Vec<u8>;
type EncryptedShare = Vec<u8>;
type Nonce = [u8; 12];

type ShamirThreshold = Threshold<ShamirTree, 0>;

#[derive(Clone, Debug)]
enum ShamirTree {
    Leaf(EncryptedShare),
    Threshold(ShamirThreshold),
}

/// Encrypts plaintext using a master secret, which is then sharded based on the descriptor.
///
/// The master secret is used with the nonce to encrypt the plaintext via ChaCha20.
/// This same master secret is then sharded into shamir shares. Each shamir share
/// is then encrypted using ChaCha20Poly1305, with keys derived from the
/// corresponding public key in the descriptor, the ciphertext, and the key index.
///
/// # Returns
/// A result containing a tuple:
///   - `Vec<EncryptedShare>`: The list of encrypted Shamir shares of the `master_encryption_key`.
///   - `Data` (Vec<u8>): The ciphertext of the `plaintext_payload`.
pub fn encrypt_with_authenticated_shards(
    descriptor: Descriptor<DescriptorPublicKey>,
    master_encryption_key: [u8; 32],
    nonce: Nonce,
    plaintext: Data,
) -> Result<(Vec<EncryptedShare>, Data)> {
    let cipher = AuthenticatedCipher {};
    encrypt_with_cipher(cipher, descriptor, master_encryption_key, nonce, plaintext)
}

/// Identical to `encrypt_with_authenticatd_shards` except shares are encrypted without
/// authentication using ChaCha20 and the payload is encrypted with authentication using
/// ChaCha20Poly1305.
///
/// This provides full secrecy to encryption, as no information is gained unless the
/// payload can be decrypted, at the cost of a combinatorial runtime to decrypt.
#[allow(dead_code)]
pub fn encrypt_with_full_secrecy(
    descriptor: Descriptor<DescriptorPublicKey>,
    master_encryption_key: [u8; 32],
    nonce: Nonce,
    plaintext: Data,
) -> Result<(Vec<EncryptedShare>, Data)> {
    let cipher = UnauthenticatedCipher {};
    encrypt_with_cipher(cipher, descriptor, master_encryption_key, nonce, plaintext)
}

/// Reconstructs the master secret from its encrypted Shamir shares and decrypts the ciphertext.
pub fn decrypt_with_authenticated_shards(
    descriptor: Descriptor<DescriptorPublicKey>,
    encrypted_shares: Vec<EncryptedShare>,
    public_keys: Vec<DescriptorPublicKey>,
    nonce: Nonce,
    ciphertext: Data,
) -> Result<Data> {
    let cipher = AuthenticatedCipher {};
    let pks = public_keys.iter().map(|pk| Some(pk)).collect();
    let tree = ShamirTree::reconstruct(&descriptor, &encrypted_shares)?;
    tree.decrypt(pks, nonce, ciphertext, &cipher)
}

/// Decrypts a payload encrypted using `encrypt_with_full_secrecy` by trying all possible combinations
/// of mappings of shares to keys, including to None. This is O((N+1)^K), where N is the number of keys
/// and K is the number of shares.
pub fn decrypt_with_full_secrecy(
    descriptor: Descriptor<DescriptorPublicKey>,
    encrypted_shares: Vec<EncryptedShare>,
    public_keys: Vec<DescriptorPublicKey>,
    nonce: Nonce,
    ciphertext: Data,
) -> Result<Data> {
    let cipher = UnauthenticatedCipher {};
    let tree = ShamirTree::reconstruct(&descriptor, &encrypted_shares)?;
    let num_slots = encrypted_shares.len();

    // Deduplicate public keys
    let mut unique_keys = public_keys.clone();
    unique_keys.sort();
    unique_keys.dedup();

    // Each slot can hold any one of the provided public keys or None.
    let mut choices_for_each_slot: Vec<Option<&DescriptorPublicKey>> =
        unique_keys.iter().map(Some).collect();
    choices_for_each_slot.push(None);

    // Create an iterator that will produce all combinations.
    let combinations_iterator = std::iter::repeat(choices_for_each_slot.iter().cloned())
        .take(num_slots)
        .multi_cartesian_product();

    // Iterate through each generated combination and attempt decryption.
    for key_combination in combinations_iterator {
        if let Ok(decrypted_payload) =
            tree.decrypt(key_combination, nonce, ciphertext.clone(), &cipher)
        {
            return Ok(decrypted_payload);
        }
    }

    Err(Error::DecryptionFailed.into())
}

fn encrypt_with_cipher<T: KeyCipher>(
    cipher: T,
    descriptor: Descriptor<DescriptorPublicKey>,
    master_encryption_key: [u8; 32],
    nonce: Nonce,
    plaintext: Data,
) -> Result<(Vec<EncryptedShare>, Data)> {
    let keyless_node = descriptor.to_tree().prune_keyless();

    ensure!(keyless_node.is_some(), Error::NoKeysRequired);

    let encrypted_payload = cipher.encrypt_payload(plaintext, master_encryption_key, nonce)?;

    let mut hasher = Sha256::new();
    hasher.update(&encrypted_payload);
    let hash = hasher.finalize();

    let tree = ShamirTree::build_tree(
        &keyless_node.unwrap(),
        master_encryption_key.to_vec(),
        &hash.as_slice().try_into().unwrap(),
        &cipher,
        &mut 0,
    )?;

    let encrypted_shares = tree.extract_encrypted_shares();
    Ok((encrypted_shares, encrypted_payload))
}

impl ShamirTree {
    /// Constructs a tree of encrypted shamir shares
    fn build_tree<T: KeyCipher>(
        node: &KeylessDescriptorTree<DescriptorPublicKey>,
        share: Data,
        hash: &[u8; 32],
        cipher: &T,
        leaf_index: &mut usize,
    ) -> Result<Self> {
        match node {
            KeylessDescriptorTree::Key(pk) => {
                let index = *leaf_index;
                *leaf_index += 1;

                Ok(ShamirTree::Leaf(
                    cipher.encrypt_share(share, &pk, hash, index)?,
                ))
            }
            KeylessDescriptorTree::Threshold(thresh) => {
                let xs: Vec<u8> = (1..=thresh.n() as u8).collect();
                let shares = split_secret(&share, thresh.k(), &xs).map_err(|e| anyhow!(e))?;
                let mut shamir_nodes = Vec::new();
                for (node, share) in thresh.iter().zip(shares.into_iter()) {
                    let tree = Self::build_tree::<T>(node, share.ys, hash, cipher, leaf_index)?;
                    shamir_nodes.push(tree);
                }
                let shamir_thresh = ShamirThreshold::new(thresh.k(), shamir_nodes)?;

                Ok(ShamirTree::Threshold(shamir_thresh))
            }
        }
    }

    /// Returns a list of encrypted shares (in order)
    fn extract_encrypted_shares(&self) -> Vec<EncryptedShare> {
        match self {
            ShamirTree::Leaf(share) => vec![share.clone()],
            ShamirTree::Threshold(thresh) => thresh
                .iter()
                .flat_map(|node| node.extract_encrypted_shares())
                .collect(),
        }
    }

    /// Reconstructs a shamir tree from a descriptor and a list of shares.
    fn reconstruct(
        descriptor: &Descriptor<DescriptorPublicKey>,
        shares: &Vec<EncryptedShare>,
    ) -> Result<Self> {
        let keyless_node = descriptor.to_tree().prune_keyless();

        ensure!(keyless_node.is_some(), Error::NoKeysRequired);

        let mut leaf_index = 0;
        let tree =
            ShamirTree::reconstruct_tree(&keyless_node.unwrap(), &shares, &mut leaf_index)?;

        ensure! {
            leaf_index == shares.len(),
            Error::TooManyShares
        }

        Ok(tree)
    }

    /// Helper function to reconstruct a shamir tree.
    fn reconstruct_tree(
        tree: &KeylessDescriptorTree<DescriptorPublicKey>,
        shares: &Vec<EncryptedShare>,
        leaf_index: &mut usize,
    ) -> Result<Self> {
        match tree {
            KeylessDescriptorTree::Key(_) => {
                ensure! {
                    *leaf_index < shares.len(),
                    Error::InsufficientShares
                }

                let index = *leaf_index;
                *leaf_index += 1;

                Ok(ShamirTree::Leaf(shares[index].clone()))
            }
            KeylessDescriptorTree::Threshold(thresh) => {
                let mut shamir_nodes = Vec::new();
                for node_inner in thresh.iter() {
                    let tree = Self::reconstruct_tree(node_inner, shares, leaf_index)?;
                    shamir_nodes.push(tree);
                }
                let shamir_thresh = ShamirThreshold::new(thresh.k(), shamir_nodes)?;

                Ok(ShamirTree::Threshold(shamir_thresh))
            }
        }
    }

    /// Decrypts ciphertext reassembling the master secret using a list of public keys
    fn decrypt<T: KeyCipher>(
        &self,
        keys: Vec<Option<&DescriptorPublicKey>>,
        nonce: Nonce,
        ciphertext: Data,
        cipher: &T,
    ) -> Result<Data> {
        let mut hasher = Sha256::new();
        hasher.update(&ciphertext);
        let hash = hasher.finalize();

        let secret = self.decrypt_tree::<T>(
            &keys,
            &hash.as_slice().try_into().unwrap(),
            cipher,
            &mut 0,
            true,
        )?;

        assert!(secret.len() == 32);

        cipher.decrypt_payload(ciphertext, secret.as_slice().try_into().unwrap(), nonce)
    }

    /// Helper function to decrypt tree of encrypted shamir shares
    fn decrypt_tree<T: KeyCipher>(
        &self,
        keys: &Vec<Option<&DescriptorPublicKey>>,
        hash: &[u8; 32],
        cipher: &T,
        leaf_index: &mut usize,
        decrypt_leaves: bool,
    ) -> Result<Data, Error> {
        match self {
            ShamirTree::Leaf(encrypted_share) => {
                let index = *leaf_index;
                *leaf_index += 1;

                if !decrypt_leaves {
                    return Ok(vec![]);
                }

                if let Ok(plaintext) =
                    cipher.decrypt_share(encrypted_share.to_vec(), keys, hash, index)
                {
                    return Ok(plaintext);
                }

                Err(Error::KeysRequired(1))
            }
            ShamirTree::Threshold(thresh) => {
                let mut shares = Vec::new();
                let mut keys_required = Vec::new();
                for (i, node) in thresh.iter().enumerate() {
                    match node.decrypt_tree::<T>(
                        keys,
                        hash,
                        cipher,
                        leaf_index,
                        shares.len() < thresh.k(),
                    ) {
                        Ok(ys) => {
                            let share = Share {
                                x: (i as u8) + 1,
                                ys,
                            };
                            shares.push(share);
                        }
                        Err(Error::KeysRequired(n)) => {
                            keys_required.push(n);
                        }
                        err => return err,
                    }
                }

                if shares.len() >= thresh.k() {
                    reconstruct_secret(&shares, thresh.k()).map_err(Error::InvalidShamir)
                } else {
                    keys_required.sort();

                    let nodes_required = thresh.k() - shares.len();
                    let min_keys_required = keys_required[0..nodes_required].iter().sum();

                    return Err(Error::KeysRequired(min_keys_required));
                }
            }
        }
    }
}

/// Error

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Descriptor does not require a key
    NoKeysRequired,
    /// Descriptor contains more keys than shares provided
    InsufficientShares,
    /// Descriptor contains fewer keys than shares provided
    TooManyShares,
    /// Invalid shamir share reconstruction
    InvalidShamir(String),
    /// Additional keys required to decrypt
    KeysRequired(usize),
    /// Unable to decrypt with any combination of keys
    DecryptionFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NoKeysRequired => write!(f, "descriptor must require a key"),
            Self::InsufficientShares => write!(f, "insufficient shares"),
            Self::TooManyShares => write!(f, "too many shares"),
            Self::InvalidShamir(err) => write!(f, "invalid shamir: {err}"),
            Self::KeysRequired(num_required) => {
                write!(f, "requires {num_required} additional key(s)")
            }
            Self::DecryptionFailed => {
                write!(f, "unable to decrypt")
            }
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1;
    use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

    const NONCE_VALUE: Nonce = [0u8; 12_usize];

    // Helper function to create test keys
    fn create_test_key(index: u32) -> DescriptorPublicKey {
        let secp = secp256k1::Secp256k1::new();
        let secret_value = 1u32 + index;

        let mut sk_bytes = [0u8; 32];
        sk_bytes[28..32].copy_from_slice(&secret_value.to_be_bytes());

        let pk = bitcoin::PublicKey {
            inner: secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&sk_bytes).expect("sk"),
            ),
            compressed: true,
        };

        DescriptorPublicKey::Single(miniscript::descriptor::SinglePub {
            key: miniscript::descriptor::SinglePubKey::FullKey(pk),
            origin: None,
        })
    }

    // Helper to create a simple threshold descriptor with n pubkeys
    fn create_threshold_descriptor(
        k: usize,
        n: usize,
    ) -> (Descriptor<DescriptorPublicKey>, Vec<DescriptorPublicKey>) {
        let mut pubkeys_vec = Vec::new();

        for i in 1..=n as u32 {
            let pubkey_val = create_test_key(3 * i);
            pubkeys_vec.push(pubkey_val);
        }

        let pubkey_strs_vec: Vec<String> = pubkeys_vec
            .iter()
            .map(|pk_val| pk_val.to_string())
            .collect();

        let desc_str = format!("wsh(multi({},{}))", k, pubkey_strs_vec.join(","));
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        (descriptor, pubkeys_vec)
    }

    // Helper to get plaintext, ciphertext, and encrypted shares
    fn get_encrypted_data(
        descriptor: Descriptor<DescriptorPublicKey>,
    ) -> (Vec<EncryptedShare>, Data, Data) {
        let master_key = [1u8; 32];
        let plaintext: Data = b"This is test plaintext".to_vec();

        let (shares, ciphertext) = encrypt_with_authenticated_shards(
            descriptor,
            master_key,
            NONCE_VALUE,
            plaintext.clone(),
        )
        .unwrap();

        (shares, plaintext, ciphertext)
    }

    // Helper to get plaintext, ciphertext, and encrypted shares using unauthenticated encryption
    fn get_encrypted_data_with_full_secrecy(
        descriptor: Descriptor<DescriptorPublicKey>,
    ) -> (Vec<EncryptedShare>, Data, Data) {
        let master_key = [1u8; 32];
        let plaintext: Data = b"This is test plaintext for unauth".to_vec();

        let (shares, ciphertext) =
            encrypt_with_full_secrecy(descriptor, master_key, NONCE_VALUE, plaintext.clone())
                .unwrap();

        (shares, plaintext, ciphertext)
    }

    #[test]
    fn test_single_key_encryption() {
        let pubkey_val = create_test_key(1);
        let desc_str = format!("wpkh({})", pubkey_val);
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone());

        assert_eq!(
            shares.len(),
            1,
            "Single key descriptor should produce one share"
        );

        let decrypted_plaintext = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            vec![pubkey_val.clone()],
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();

        assert_eq!(
            decrypted_plaintext, plaintext,
            "Decrypted plaintext doesn't match original"
        );

        // Test decryption with an incorrect public key.
        let wrong_key_val = create_test_key(2);
        let result = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            vec![wrong_key_val],
            NONCE_VALUE,
            ciphertext,
        );
        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_multi_key_threshold_1of2() {
        let (descriptor, pubkeys_vec) = create_threshold_descriptor(1, 2);

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone());

        assert_eq!(shares.len(), 2, "1-of-2 multisig should produce 2 shares");

        // Test with different key combinations
        for i in 0..2 {
            let key_subset_vec = vec![pubkeys_vec[i].clone()];
            let decrypted_plaintext = decrypt_with_authenticated_shards(
                descriptor.clone(),
                shares.clone(),
                key_subset_vec,
                NONCE_VALUE,
                ciphertext.clone(),
            )
            .unwrap();

            assert_eq!(
                decrypted_plaintext, plaintext,
                "Decrypted plaintext doesn't match original"
            );
        }
    }

    #[test]
    fn test_multi_key_threshold_2of3() {
        let (descriptor, pubkeys_vec) = create_threshold_descriptor(2, 3);

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone());

        assert_eq!(shares.len(), 3, "2-of-3 multisig should produce 3 shares");

        // Test with different key combinations
        for i in 0..3 {
            for j in (i + 1)..3 {
                let key_subset_vec = vec![pubkeys_vec[i].clone(), pubkeys_vec[j].clone()];
                let decrypted_plaintext = decrypt_with_authenticated_shards(
                    descriptor.clone(),
                    shares.clone(),
                    key_subset_vec,
                    NONCE_VALUE,
                    ciphertext.clone(),
                )
                .unwrap();

                assert_eq!(
                    decrypted_plaintext, plaintext,
                    "Decrypted plaintext doesn't match original"
                );
            }
        }

        // Test with insufficient keys (should fail)
        for i in 0..3 {
            let single_key_vec = vec![pubkeys_vec[i].clone()];
            let result = decrypt_with_authenticated_shards(
                descriptor.clone(),
                shares.clone(),
                single_key_vec,
                NONCE_VALUE,
                ciphertext.clone(),
            );

            assert!(
                result.is_err(),
                "Decryption should fail with only 1 key for 2-of-3"
            );
        }
    }

    #[test]
    fn test_multi_key_threshold_3of5() {
        let (descriptor, pubkeys) = create_threshold_descriptor(3, 5);

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone());

        assert_eq!(shares.len(), 5, "3-of-5 multisig should produce 5 shares");

        let key_subset_exact = vec![pubkeys[0].clone(), pubkeys[2].clone(), pubkeys[4].clone()];
        let decrypted_exact = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset_exact,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();

        assert_eq!(
            decrypted_exact, plaintext,
            "Decrypted plaintext doesn't match original with exact keys"
        );

        let key_subset_more = vec![
            pubkeys[0].clone(),
            pubkeys[1].clone(),
            pubkeys[2].clone(),
            pubkeys[3].clone(),
        ];
        let decrypted_more = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset_more,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();

        assert_eq!(
            decrypted_more, plaintext,
            "Decrypted plaintext doesn't match original with more keys"
        );

        let key_subset_less = vec![pubkeys[0].clone(), pubkeys[1].clone()];
        let decrypted_less = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset_less,
            NONCE_VALUE,
            ciphertext.clone(),
        );

        assert!(
            decrypted_less.is_err(),
            "Decryption should fail with only 2 keys for 3-of-5"
        );
    }

    #[test]
    fn test_nested_thresholds() {
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);
        let key4 = create_test_key(4);

        let desc_str = format!(
            "wsh(thresh(2,or_d(pk({}),pk({})),s:pk({}),s:pk({})))",
            key1, key2, key3, key4
        );
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone());
        assert_eq!(shares.len(), 4, "Nested thresholds should produce 4 shares");

        // Test case 1: key3 + key4 (satisfies outer threshold)
        let key_subset1 = vec![key3.clone(), key4.clone()];
        let decrypted1 = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset1,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();
        assert_eq!(decrypted1, plaintext, "Mismatch for key3 + key4");

        // Test case 2: key1 + key3 (key1 from inner, key3 from outer)
        let key_subset2 = vec![key1.clone(), key3.clone()];
        let decrypted2 = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset2,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();
        assert_eq!(decrypted2, plaintext, "Mismatch for key1 + key3");

        // Test case 3: key1 + key4 (key1 from inner, key4 from outer)
        let key_subset2 = vec![key1.clone(), key4.clone()];
        let decrypted2 = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset2,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();
        assert_eq!(decrypted2, plaintext, "Mismatch for key1 + key3");

        // Test case 4: key2 + key3 (key2 from inner, key3 from outer)
        let key_subset2 = vec![key2.clone(), key3.clone()];
        let decrypted2 = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset2,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();
        assert_eq!(decrypted2, plaintext, "Mismatch for key1 + key3");

        // Test case 5: only key3 (insufficient)
        let key_subset_insufficient1 = vec![key3.clone()];
        let decrypted_insufficient1 = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset_insufficient1,
            NONCE_VALUE,
            ciphertext.clone(),
        );
        assert!(
            decrypted_insufficient1.is_err(),
            "Decryption should fail with only key3"
        );

        // Test case 6: key1 + key2 (both from inner threshold, but insufficient for outer)
        let key_subset_insufficient2 = vec![key1.clone(), key2.clone()];
        let decrypted_insufficient2 = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares.clone(),
            key_subset_insufficient2,
            NONCE_VALUE,
            ciphertext.clone(),
        );
        assert!(
            decrypted_insufficient2.is_err(),
            "Decryption should fail with only inner threshold keys (key1+key2)"
        );
    }

    #[test]
    fn test_reconstruction_with_incorrect_shares_content() {
        let (descriptor, pubkeys) = create_threshold_descriptor(2, 3);

        let (mut shares, _, ciphertext) = get_encrypted_data(descriptor.clone());

        // Corrupt one of the shares
        if !shares.is_empty() {
            shares[0] = [2u8; 48].to_vec();
        }

        let key_subset = vec![pubkeys[0].clone(), pubkeys[1].clone()];

        let decrypted_plaintext = decrypt_with_authenticated_shards(
            descriptor.clone(),
            shares,
            key_subset,
            NONCE_VALUE,
            ciphertext.clone(),
        );
        assert!(
            decrypted_plaintext.is_err(),
            "Decryption should fail when share content is corrupted leading to incorrect secret reconstruction"
        );
    }

    #[test]
    fn test_error_conditions() {
        // Test 1: A keyless descriptor for encryption
        let desc_pk_keyless = Descriptor::<DescriptorPublicKey>::from_str("wsh(1)").unwrap();
        let master_key = [1u8; 32];
        let p_text: Data = b"Test".to_vec();

        let result = encrypt_with_authenticated_shards(
            desc_pk_keyless.clone(),
            master_key,
            NONCE_VALUE,
            p_text.clone(),
        );
        assert!(
            result.is_err(),
            "Encryption should fail with a keyless descriptor"
        );

        let (valid_descriptor, pubkeys_valid) = create_threshold_descriptor(1, 1);
        let (shares_valid, _, ciphertext_valid) = get_encrypted_data(valid_descriptor.clone());

        // Test 2: Recover with too few shares
        let (desc_2_of_3, keys_2_of_3) = create_threshold_descriptor(2, 3);
        let one_share: Vec<EncryptedShare> = vec![[2u8; 48].to_vec()];

        let result = decrypt_with_authenticated_shards(
            desc_2_of_3.clone(),
            one_share,
            keys_2_of_3.iter().take(2).cloned().collect(),
            NONCE_VALUE,
            ciphertext_valid.clone(),
        );
        assert!(result.is_err(), "Recovery should fail if too few shares");

        // Test 3: Recover with too many shares
        let (desc_1_of_1, keys_1_of_1) = create_threshold_descriptor(1, 1);
        let two_shares: Vec<EncryptedShare> = vec![[2u8; 48].to_vec(), [3u8; 48].to_vec()];

        let result = decrypt_with_authenticated_shards(
            desc_1_of_1.clone(),
            two_shares,
            keys_1_of_1,
            NONCE_VALUE,
            ciphertext_valid.clone(),
        );
        assert!(result.is_err(), "Recovery should fail if too many shares");

        // Test 4: Decrypt with wrong ciphertext
        let wrong_ciphertext = b"Wrong encryption context".to_vec();
        let result = decrypt_with_authenticated_shards(
            valid_descriptor.clone(),
            shares_valid.clone(),
            pubkeys_valid.clone(),
            NONCE_VALUE,
            wrong_ciphertext,
        );
        assert!(
            result.is_err(),
            "Decryption should fail with wrong ciphertext"
        );
    }

    /// With Full Secrecy

    #[test]
    fn test_single_key_encryption_with_full_secrecy() {
        let pubkey_val = create_test_key(101);
        let desc_str = format!("wpkh({})", pubkey_val);
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let (shares, plaintext, ciphertext) =
            get_encrypted_data_with_full_secrecy(descriptor.clone());

        assert_eq!(
            shares.len(),
            1,
            "Single key descriptor should produce one share"
        );

        let decrypted_plaintext = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            vec![pubkey_val.clone()],
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();

        assert_eq!(
            decrypted_plaintext, plaintext,
            "Decrypted plaintext doesn't match original (unauthenticated)"
        );

        let wrong_key_val = create_test_key(102);
        let result = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            vec![wrong_key_val],
            NONCE_VALUE,
            ciphertext,
        );
        assert!(
            result.is_err(),
            "Decryption should fail with wrong key (unauthenticated)"
        );
        assert_eq!(
            result.unwrap_err().downcast_ref::<Error>().unwrap(),
            &Error::DecryptionFailed
        );
    }

    #[test]
    fn test_multi_key_threshold_1of2_with_full_secrecy() {
        let (descriptor, pubkeys_vec) = create_threshold_descriptor(1, 2);
        let (shares, plaintext, ciphertext) =
            get_encrypted_data_with_full_secrecy(descriptor.clone());

        assert_eq!(
            shares.len(),
            2,
            "1-of-2 multisig should produce 2 shares (unauthenticated)"
        );

        for i in 0..2 {
            let key_subset_vec = vec![pubkeys_vec[i].clone()];
            let decrypted_plaintext = decrypt_with_full_secrecy(
                descriptor.clone(),
                shares.clone(),
                key_subset_vec,
                NONCE_VALUE,
                ciphertext.clone(),
            )
            .unwrap();

            assert_eq!(
                decrypted_plaintext, plaintext,
                "Decrypted plaintext doesn't match original (unauthenticated)"
            );
        }
    }

    #[test]
    fn test_multi_key_threshold_2of3_with_full_secrecy() {
        let (descriptor, pubkeys_vec) = create_threshold_descriptor(2, 3);
        let (shares, plaintext, ciphertext) =
            get_encrypted_data_with_full_secrecy(descriptor.clone());

        assert_eq!(
            shares.len(),
            3,
            "2-of-3 multisig should produce 3 shares (unauthenticated)"
        );

        for i in 0..3 {
            for j in (i + 1)..3 {
                let key_subset_vec = vec![pubkeys_vec[i].clone(), pubkeys_vec[j].clone()];
                let decrypted_plaintext = decrypt_with_full_secrecy(
                    descriptor.clone(),
                    shares.clone(),
                    key_subset_vec,
                    NONCE_VALUE,
                    ciphertext.clone(),
                )
                .unwrap();

                assert_eq!(
                    decrypted_plaintext, plaintext,
                    "Decrypted plaintext doesn't match original (unauthenticated)"
                );
            }
        }

        for i in 0..3 {
            let single_key_vec = vec![pubkeys_vec[i].clone()];
            let result = decrypt_with_full_secrecy(
                descriptor.clone(),
                shares.clone(),
                single_key_vec,
                NONCE_VALUE,
                ciphertext.clone(),
            );

            assert!(
                result.is_err(),
                "Decryption should fail with only 1 key for 2-of-3 (unauthenticated)"
            );
            assert_eq!(
                result.unwrap_err().downcast_ref::<Error>().unwrap(),
                &Error::DecryptionFailed
            );
        }
    }

    #[test]
    fn test_multi_key_threshold_3of5_with_full_secrecy() {
        let (descriptor, pubkeys) = create_threshold_descriptor(3, 5);
        let (shares, plaintext, ciphertext) =
            get_encrypted_data_with_full_secrecy(descriptor.clone());

        assert_eq!(
            shares.len(),
            5,
            "3-of-5 multisig should produce 5 shares (unauthenticated)"
        );

        let key_subset_exact = vec![pubkeys[0].clone(), pubkeys[2].clone(), pubkeys[4].clone()];
        let decrypted_exact = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            key_subset_exact,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();
        assert_eq!(
            decrypted_exact, plaintext,
            "Decrypted plaintext doesn't match original with exact keys (unauthenticated)"
        );

        let key_subset_more = vec![
            pubkeys[0].clone(),
            pubkeys[1].clone(),
            pubkeys[2].clone(),
            pubkeys[3].clone(),
        ];
        let decrypted_more = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            key_subset_more,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();
        assert_eq!(
            decrypted_more, plaintext,
            "Decrypted plaintext doesn't match original with more keys (unauthenticated)"
        );

        let key_subset_less = vec![pubkeys[0].clone(), pubkeys[1].clone()];
        let decrypted_less = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            key_subset_less,
            NONCE_VALUE,
            ciphertext.clone(),
        );
        assert!(
            decrypted_less.is_err(),
            "Decryption should fail with only 2 keys for 3-of-5 (unauthenticated)"
        );
        assert_eq!(
            decrypted_less.unwrap_err().downcast_ref::<Error>().unwrap(),
            &Error::DecryptionFailed
        );
    }

    #[test]
    fn test_nested_thresholds_with_full_secrecy() {
        let key1 = create_test_key(201);
        let key2 = create_test_key(202);
        let key3 = create_test_key(203);
        let key4 = create_test_key(204);

        let desc_str = format!(
            "wsh(thresh(2,or_d(pk({}),pk({})),s:pk({}),s:pk({})))",
            key1, key2, key3, key4
        );
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();
        let (shares, plaintext, ciphertext) =
            get_encrypted_data_with_full_secrecy(descriptor.clone());
        assert_eq!(
            shares.len(),
            4,
            "Nested thresholds should produce 4 shares (unauthenticated)"
        );

        let key_subset1 = vec![key3.clone(), key4.clone()];
        let decrypted1 = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            key_subset1,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();
        assert_eq!(
            decrypted1, plaintext,
            "Mismatch for key3 + key4 (unauthenticated)"
        );

        let key_subset2 = vec![key1.clone(), key3.clone()];
        let decrypted2 = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            key_subset2,
            NONCE_VALUE,
            ciphertext.clone(),
        )
        .unwrap();
        assert_eq!(
            decrypted2, plaintext,
            "Mismatch for key1 + key3 (unauthenticated)"
        );

        let key_subset_insufficient1 = vec![key3.clone()];
        let decrypted_insufficient1 = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            key_subset_insufficient1,
            NONCE_VALUE,
            ciphertext.clone(),
        );
        assert!(
            decrypted_insufficient1.is_err(),
            "Decryption should fail with only key3 (unauthenticated)"
        );
        assert_eq!(
            decrypted_insufficient1
                .unwrap_err()
                .downcast_ref::<Error>()
                .unwrap(),
            &Error::DecryptionFailed
        );

        let key_subset_insufficient2 = vec![key1.clone(), key2.clone()];
        let decrypted_insufficient2 = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares.clone(),
            key_subset_insufficient2,
            NONCE_VALUE,
            ciphertext.clone(),
        );
        assert!(
            decrypted_insufficient2.is_err(),
            "Decryption should fail with only inner threshold keys (unauthenticated)"
        );
        assert_eq!(
            decrypted_insufficient2
                .unwrap_err()
                .downcast_ref::<Error>()
                .unwrap(),
            &Error::DecryptionFailed
        );
    }

    #[test]
    fn test_reconstruction_with_incorrect_shares_content_with_full_secrecy() {
        let (descriptor, pubkeys) = create_threshold_descriptor(2, 3);
        let (mut shares, _plaintext, ciphertext) =
            get_encrypted_data_with_full_secrecy(descriptor.clone());

        if !shares.is_empty() {
            shares[0] = [2u8; 32].to_vec(); // Unauthenticated shares are 32 bytes
        }

        let key_subset = vec![pubkeys[0].clone(), pubkeys[1].clone()];
        let decrypted_plaintext = decrypt_with_full_secrecy(
            descriptor.clone(),
            shares,
            key_subset,
            NONCE_VALUE,
            ciphertext.clone(),
        );
        assert!(
            decrypted_plaintext.is_err(),
            "Decryption should fail when share content is corrupted (unauthenticated)"
        );
        assert_eq!(
            decrypted_plaintext
                .unwrap_err()
                .downcast_ref::<Error>()
                .unwrap(),
            &Error::DecryptionFailed
        );
    }

    #[test]
    fn test_error_conditions_with_full_secrecy() {
        // Test 1: A keyless descriptor for encryption
        let desc_pk_keyless = Descriptor::<DescriptorPublicKey>::from_str("wsh(1)").unwrap();
        let master_key = [1u8; 32];
        let p_text: Data = b"Test".to_vec();

        let result = encrypt_with_full_secrecy(
            desc_pk_keyless.clone(),
            master_key,
            NONCE_VALUE,
            p_text.clone(),
        );
        assert!(
            result.is_err(),
            "Encryption should fail with a keyless descriptor"
        );

        let (valid_descriptor, pubkeys_valid) = create_threshold_descriptor(1, 1);
        let (shares_valid, _, ciphertext_valid) =
            get_encrypted_data_with_full_secrecy(valid_descriptor.clone());

        // Test 2: Recover with too few shares
        let (desc_2_of_3, keys_2_of_3) = create_threshold_descriptor(2, 3);
        let one_share: Vec<EncryptedShare> = vec![[2u8; 48].to_vec()];

        let result = decrypt_with_full_secrecy(
            desc_2_of_3.clone(),
            one_share,
            keys_2_of_3.iter().take(2).cloned().collect(),
            NONCE_VALUE,
            ciphertext_valid.clone(),
        );
        assert!(result.is_err(), "Recovery should fail if too few shares");

        // Test 3: Recover with too many shares
        let (desc_1_of_1, keys_1_of_1) = create_threshold_descriptor(1, 1);
        let two_shares: Vec<EncryptedShare> = vec![[2u8; 48].to_vec(), [3u8; 48].to_vec()];

        let result = decrypt_with_full_secrecy(
            desc_1_of_1.clone(),
            two_shares,
            keys_1_of_1,
            NONCE_VALUE,
            ciphertext_valid.clone(),
        );
        assert!(result.is_err(), "Recovery should fail if too many shares");

        // Test 4: Decrypt with wrong ciphertext
        let wrong_ciphertext = b"Wrong encryption context".to_vec();
        let result = decrypt_with_full_secrecy(
            valid_descriptor.clone(),
            shares_valid.clone(),
            pubkeys_valid.clone(),
            NONCE_VALUE,
            wrong_ciphertext,
        );
        assert!(
            result.is_err(),
            "Decryption should fail with wrong ciphertext"
        );
    }
}
