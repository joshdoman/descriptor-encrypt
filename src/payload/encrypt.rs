// SPDX-License-Identifier: CC0-1.0

use anyhow::{Result, anyhow, ensure};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use miniscript::{
    Threshold,
    descriptor::{Descriptor, DescriptorPublicKey, SinglePubKey},
};
use sha2::{Digest, Sha256};

use super::descriptor_node::{DescriptorNode, ToDescriptorNode};
use super::shamir::{Share, reconstruct_secret, split_secret};

type Data = Vec<u8>;
type EncryptedShare = [u8; 48];
type Nonce = [u8; 12];
type Secret = [u8; 32];

type ShamirThreshold = Threshold<ShamirNode, 0>;

#[derive(Clone, Debug)]
enum ShamirNode {
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
/// # Arguments
/// - `descriptor_node`: The descriptor governing how the master secret is sharded and keys are derived.
/// - `master_encryption_key`: The 32-byte secret key. This key is used for primary payload encryption AND is the secret that gets sharded.
/// - `nonce`: The 12-byte nonce for encrypting the `plaintext`.
/// - `plaintext`: The data to be encrypted.
///
/// # Returns
/// A result containing a tuple:
///   - `Vec<EncryptedShare>`: The list of encrypted Shamir shares of the `master_encryption_key`.
///   - `Data` (Vec<u8>): The ciphertext of the `plaintext_payload`.
pub fn encrypt_payload_and_shard_key(
    descriptor: Descriptor<DescriptorPublicKey>,
    master_encryption_key: Secret,
    nonce: Nonce,
    plaintext: Data,
) -> Result<(Vec<EncryptedShare>, Data)> {
    let keyless_node = descriptor.to_node().prune_keyless();

    ensure!(keyless_node.is_some(), Error::NoKeysRequired);

    let mut cipher = ChaCha20::new(&master_encryption_key.into(), &nonce.into());
    let mut buffer = plaintext.clone();
    cipher.apply_keystream(&mut buffer);
    let ciphertext = buffer.clone();

    let mut hasher = Sha256::new();
    hasher.update(&ciphertext);
    let hash = hasher.finalize();

    let tree = ShamirNode::build_tree(
        &keyless_node.unwrap(),
        master_encryption_key.to_vec(),
        &hash.to_vec(),
        &mut 0,
    )?;

    let encrypted_shares = tree.extract_encrypted_shares();
    Ok((encrypted_shares, ciphertext))
}

/// Reconstructs the master secret from its encrypted Shamir shares and decrypts the payload ciphertext.
///
/// # Arguments
/// - `descriptor_node`: The descriptor used during encryption.
/// - `encrypted_shares`: The list of encrypted Shamir shares of the master secret.
/// - `public_keys`: The public keys available to attempt decryption of shares.
/// - `nonce`: The 12-byte nonce used for the original payload encryption.
/// - `ciphertext`: The ciphertext of the payload to be decrypted.
///
/// # Returns
/// A result containing the decrypted plaintext payload `Data`.
pub fn recover_key_and_decrypt_payload(
    descriptor: Descriptor<DescriptorPublicKey>,
    encrypted_shares: Vec<EncryptedShare>,
    public_keys: Vec<DescriptorPublicKey>,
    nonce: Nonce,
    ciphertext: Data,
) -> Result<Data> {
    let keyless_node = descriptor.to_node().prune_keyless();

    ensure!(keyless_node.is_some(), Error::NoKeysRequired);

    let mut leaf_index = 0;
    let tree =
        ShamirNode::reconstruct_tree(&keyless_node.unwrap(), &encrypted_shares, &mut leaf_index)?;

    ensure! {
        leaf_index == encrypted_shares.len(),
        Error::TooManyShares
    }

    tree.decrypt(public_keys, nonce, ciphertext)
}

impl ShamirNode {
    /// Constructs a tree of encrypted shamir shares
    fn build_tree(
        node: &DescriptorNode<DescriptorPublicKey>,
        share: Data,
        hash: &Data,
        leaf_index: &mut usize,
    ) -> Result<Self> {
        match node {
            DescriptorNode::Key(pk) => {
                let (nonce, cipher) = Self::get_cipher(pk, hash, *leaf_index)?;
                let encrypted_share = cipher
                    .encrypt(&nonce, share.as_ref())
                    .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 encryption error: {:?}", e))?;
                *leaf_index += 1;

                assert_eq!(encrypted_share.len(), 48);

                Ok(ShamirNode::Leaf(
                    encrypted_share.as_slice().try_into().unwrap(),
                ))
            }
            DescriptorNode::Threshold(thresh) => {
                let xs: Vec<u8> = (1..=thresh.n() as u8).collect();
                let shares = split_secret(&share, thresh.k(), &xs).map_err(|e| anyhow!(e))?;
                let mut shamir_nodes = Vec::new();
                for (node, share) in thresh.iter().zip(shares.into_iter()) {
                    let tree = Self::build_tree(node, share.ys, hash, leaf_index)?;
                    shamir_nodes.push(tree);
                }
                let shamir_thresh = ShamirThreshold::new(thresh.k(), shamir_nodes)?;

                Ok(ShamirNode::Threshold(shamir_thresh))
            }
            DescriptorNode::Keyless() => unreachable!("node is keyless"),
        }
    }

    /// Returns a list of encrypted shares (in order)
    fn extract_encrypted_shares(&self) -> Vec<EncryptedShare> {
        match self {
            ShamirNode::Leaf(share) => vec![*share],
            ShamirNode::Threshold(thresh) => thresh
                .iter()
                .flat_map(|node| node.extract_encrypted_shares())
                .collect(),
        }
    }

    /// Reconstructs a shamir node from a descriptor node and a list of shares.
    fn reconstruct_tree(
        node: &DescriptorNode<DescriptorPublicKey>,
        shares: &Vec<EncryptedShare>,
        leaf_index: &mut usize,
    ) -> Result<Self> {
        match node {
            DescriptorNode::Key(_) => {
                ensure! {
                    *leaf_index < shares.len(),
                    Error::InsufficientShares
                }

                let encrypted_share = shares[*leaf_index];
                *leaf_index += 1;

                Ok(ShamirNode::Leaf(encrypted_share))
            }
            DescriptorNode::Threshold(thresh) => {
                let mut shamir_nodes = Vec::new();
                for node_inner in thresh.iter() {
                    let tree = Self::reconstruct_tree(node_inner, shares, leaf_index)?;
                    shamir_nodes.push(tree);
                }
                let shamir_thresh = ShamirThreshold::new(thresh.k(), shamir_nodes)?;

                Ok(ShamirNode::Threshold(shamir_thresh))
            }
            DescriptorNode::Keyless() => unreachable!("node is keyless"),
        }
    }

    /// Decrypts ciphertext reassembling the master secret using a list of public keys
    fn decrypt(
        &self,
        keys: Vec<DescriptorPublicKey>,
        nonce: Nonce,
        ciphertext: Data,
    ) -> Result<Data> {
        let mut hasher = Sha256::new();
        hasher.update(&ciphertext);
        let hash = hasher.finalize();

        let secret = self.decrypt_tree(&keys, &hash.to_vec(), &mut 0, true)?;

        assert!(secret.len() == 32);

        let key: [u8; 32] = secret.as_slice().try_into().unwrap();
        let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
        let mut buffer = ciphertext.clone();
        cipher.apply_keystream(&mut buffer);
        let plaintext = buffer;

        Ok(plaintext)
    }

    /// Helper function to decrypt tree of encrypted shamir shares
    fn decrypt_tree(
        &self,
        keys: &Vec<DescriptorPublicKey>,
        hash: &Data,
        leaf_index: &mut usize,
        decrypt_leaves: bool,
    ) -> Result<Data, Error> {
        match self {
            ShamirNode::Leaf(encrypted_share) => {
                let index = *leaf_index;
                *leaf_index += 1;

                if !decrypt_leaves {
                    return Ok(vec![]);
                }

                for key in keys {
                    let Ok((nonce, cipher)) = Self::get_cipher(key, hash, index) else {
                        continue;
                    };
                    let Ok(result) = cipher.decrypt(&nonce, encrypted_share.as_ref()) else {
                        continue;
                    };

                    return Ok(result);
                }

                Err(Error::KeysRequired(1))
            }
            ShamirNode::Threshold(thresh) => {
                let mut shares = Vec::new();
                let mut keys_required = Vec::new();
                for (i, node) in thresh.iter().enumerate() {
                    match node.decrypt_tree(keys, hash, leaf_index, shares.len() < thresh.k()) {
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

    /// Returns nonce and ChaCha20-Poly1305 cipher to encrypt and decrypt data
    fn get_cipher(
        pk: &DescriptorPublicKey,
        hash: &Data,
        leaf_index: usize,
    ) -> Result<(chacha20poly1305::Nonce, ChaCha20Poly1305)> {
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
        let final_key = hasher.finalize();

        // We can safely use a zero nonce because the key is unique to the ciphertext and index
        let nonce = [0u8; 12];
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(&final_key)
            .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 key error: {:?}", e))?;

        Ok((*nonce, cipher))
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
    ) -> Result<(Vec<EncryptedShare>, Data, Data)> {
        let master_key: Secret = [1u8; 32];
        let plaintext: Data = b"This is test plaintext".to_vec();

        let (shares, ciphertext) =
            encrypt_payload_and_shard_key(descriptor, master_key, NONCE_VALUE, plaintext.clone())?;

        Ok((shares, plaintext, ciphertext))
    }

    #[test]
    fn test_single_key_encryption() -> Result<()> {
        let pubkey_val = create_test_key(1);
        let desc_str = format!("wpkh({})", pubkey_val);
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc_str)?;

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone())?;

        assert_eq!(
            shares.len(),
            1,
            "Single key descriptor should produce one share"
        );

        let decrypted_plaintext = recover_key_and_decrypt_payload(
            descriptor.clone(),
            shares.clone(),
            vec![pubkey_val.clone()],
            NONCE_VALUE,
            ciphertext.clone(),
        )?;

        assert_eq!(
            decrypted_plaintext, plaintext,
            "Decrypted plaintext doesn't match original"
        );

        // Test decryption with an incorrect public key.
        let wrong_key_val = create_test_key(2);
        let result = recover_key_and_decrypt_payload(
            descriptor.clone(),
            shares.clone(),
            vec![wrong_key_val],
            NONCE_VALUE,
            ciphertext,
        );
        assert!(result.is_err(), "Decryption should fail with wrong key");

        Ok(())
    }

    #[test]
    fn test_multi_key_threshold_1of2() -> Result<()> {
        let (descriptor, pubkeys_vec) = create_threshold_descriptor(1, 2);

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone())?;

        assert_eq!(shares.len(), 2, "1-of-2 multisig should produce 2 shares");

        // Test with different key combinations
        for i in 0..2 {
            let key_subset_vec = vec![pubkeys_vec[i].clone()];
            let decrypted_plaintext = recover_key_and_decrypt_payload(
                descriptor.clone(),
                shares.clone(),
                key_subset_vec,
                NONCE_VALUE,
                ciphertext.clone(),
            )?;
            assert_eq!(
                decrypted_plaintext, plaintext,
                "Decrypted plaintext doesn't match original"
            );
        }
        Ok(())
    }

    #[test]
    fn test_multi_key_threshold_2of3() -> Result<()> {
        let (descriptor, pubkeys_vec) = create_threshold_descriptor(2, 3);

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone())?;

        assert_eq!(shares.len(), 3, "2-of-3 multisig should produce 3 shares");

        // Test with different key combinations
        for i in 0..3 {
            for j in (i + 1)..3 {
                let key_subset_vec = vec![pubkeys_vec[i].clone(), pubkeys_vec[j].clone()];
                let decrypted_plaintext = recover_key_and_decrypt_payload(
                    descriptor.clone(),
                    shares.clone(),
                    key_subset_vec,
                    NONCE_VALUE,
                    ciphertext.clone(),
                )?;
                assert_eq!(
                    decrypted_plaintext, plaintext,
                    "Decrypted plaintext doesn't match original"
                );
            }
        }

        // Test with insufficient keys (should fail)
        for i in 0..3 {
            let single_key_vec = vec![pubkeys_vec[i].clone()];
            let result = recover_key_and_decrypt_payload(
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
        Ok(())
    }

    #[test]
    fn test_multi_key_threshold_3of5() -> Result<()> {
        let (descriptor, pubkeys) = create_threshold_descriptor(3, 5);

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone())?;

        assert_eq!(shares.len(), 5, "3-of-5 multisig should produce 5 shares");

        let key_subset_exact = vec![pubkeys[0].clone(), pubkeys[2].clone(), pubkeys[4].clone()];
        let decrypted_exact = recover_key_and_decrypt_payload(
            descriptor.clone(),
            shares.clone(),
            key_subset_exact,
            NONCE_VALUE,
            ciphertext.clone(),
        )?;
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
        let decrypted_more = recover_key_and_decrypt_payload(
            descriptor.clone(),
            shares.clone(),
            key_subset_more,
            NONCE_VALUE,
            ciphertext.clone(),
        )?;
        assert_eq!(
            decrypted_more, plaintext,
            "Decrypted plaintext doesn't match original with more keys"
        );

        let key_subset_less = vec![pubkeys[0].clone(), pubkeys[1].clone()];
        let decrypted_less = recover_key_and_decrypt_payload(
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

        Ok(())
    }

    #[test]
    fn test_nested_thresholds() -> Result<()> {
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);
        let key4 = create_test_key(4);

        let desc_str = format!(
            "wsh(thresh(2,or_d(pk({}),pk({})),s:pk({}),s:pk({})))",
            key1, key2, key3, key4
        );
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&desc_str)?;

        let (shares, plaintext, ciphertext) = get_encrypted_data(descriptor.clone())?;
        assert_eq!(shares.len(), 4, "Nested thresholds should produce 4 shares");

        // Test case 1: key3 + key4 (satisfies outer threshold)
        let key_subset1 = vec![key3.clone(), key4.clone()];
        let decrypted1 = recover_key_and_decrypt_payload(
            descriptor.clone(),
            shares.clone(),
            key_subset1,
            NONCE_VALUE,
            ciphertext.clone(),
        )?;
        assert_eq!(decrypted1, plaintext, "Mismatch for key3 + key4");

        // Test case 2: key1 + key3 (key1 from inner, key3 from outer)
        let key_subset2 = vec![key1.clone(), key3.clone()];
        let decrypted2 = recover_key_and_decrypt_payload(
            descriptor.clone(),
            shares.clone(),
            key_subset2,
            NONCE_VALUE,
            ciphertext.clone(),
        )?;
        assert_eq!(decrypted2, plaintext, "Mismatch for key1 + key3");

        // Test case 3: key1 + key4 (key1 from inner, key4 from outer)
        let key_subset2 = vec![key1.clone(), key4.clone()];
        let decrypted2 = recover_key_and_decrypt_payload(
            descriptor.clone(),
            shares.clone(),
            key_subset2,
            NONCE_VALUE,
            ciphertext.clone(),
        )?;
        assert_eq!(decrypted2, plaintext, "Mismatch for key1 + key3");

        // Test case 4: key2 + key3 (key2 from inner, key3 from outer)
        let key_subset2 = vec![key2.clone(), key3.clone()];
        let decrypted2 = recover_key_and_decrypt_payload(
            descriptor.clone(),
            shares.clone(),
            key_subset2,
            NONCE_VALUE,
            ciphertext.clone(),
        )?;
        assert_eq!(decrypted2, plaintext, "Mismatch for key1 + key3");

        // Test case 5: only key3 (insufficient)
        let key_subset_insufficient1 = vec![key3.clone()];
        let decrypted_insufficient1 = recover_key_and_decrypt_payload(
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
        let decrypted_insufficient2 = recover_key_and_decrypt_payload(
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

        Ok(())
    }

    #[test]
    fn test_reconstruction_with_incorrect_shares_content() -> Result<()> {
        let (descriptor, pubkeys) = create_threshold_descriptor(2, 3);

        let (mut shares, _, ciphertext) = get_encrypted_data(descriptor.clone())?;

        // Corrupt one of the shares
        if !shares.is_empty() {
            shares[0] = [2u8; 48];
        }

        let key_subset = vec![pubkeys[0].clone(), pubkeys[1].clone()];

        let decrypted_plaintext = recover_key_and_decrypt_payload(
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

        Ok(())
    }

    #[test]
    fn test_error_conditions() -> Result<()> {
        // Test 1: A keyless descriptor for encryption
        let desc_pk_keyless = Descriptor::<DescriptorPublicKey>::from_str("wsh(1)")?;
        let master_key: Secret = [1u8; 32];
        let p_text: Data = b"Test".to_vec();

        let result = encrypt_payload_and_shard_key(
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
        let (shares_valid, _, ciphertext_valid) = get_encrypted_data(valid_descriptor.clone())?;

        // Test 2: Recover with too few shares
        let (desc_2_of_3, keys_2_of_3) = create_threshold_descriptor(2, 3);
        let one_share: Vec<EncryptedShare> = vec![[2u8; 48]];

        let result = recover_key_and_decrypt_payload(
            desc_2_of_3.clone(),
            one_share,
            keys_2_of_3.iter().take(2).cloned().collect(),
            NONCE_VALUE,
            ciphertext_valid.clone(),
        );
        assert!(result.is_err(), "Recovery should fail if too few shares");

        // Test 3: Recover with too many shares
        let (desc_1_of_1, keys_1_of_1) = create_threshold_descriptor(1, 1);
        let two_shares: Vec<EncryptedShare> = vec![[2u8; 48], [3u8; 48]];

        let result = recover_key_and_decrypt_payload(
            desc_1_of_1.clone(),
            two_shares,
            keys_1_of_1,
            NONCE_VALUE,
            ciphertext_valid.clone(),
        );
        assert!(result.is_err(), "Recovery should fail if too many shares");

        // Test 4: Decrypt with wrong ciphertext
        let wrong_ciphertext = b"Wrong encryption context".to_vec();
        let result = recover_key_and_decrypt_payload(
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

        Ok(())
    }
}
