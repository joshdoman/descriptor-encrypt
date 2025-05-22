// Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// SPDX-License-Identifier: CC0-1.0

//! # Descriptor Encrypt
//!
//! A cryptographic system that encrypts Bitcoin wallet descriptors such that only those
//! who can spend the funds can recover the descriptor.
//!
//! ## Overview
//!
//! Bitcoin wallet descriptors encode the spending conditions for Bitcoin outputs, including
//! keys, scripts, and other requirements. While descriptors are powerful tools for representing
//! wallet structures, securely backing them up presents a challenge - especially for
//! multi-signature and complex script setups.
//!
//! This library implements a cryptographic system that allows any Bitcoin wallet descriptor to be
//! encrypted with a security model that directly mirrors the descriptor's spending conditions:
//!
//! - If your wallet requires 2-of-3 keys to spend, it will require exactly 2-of-3 keys to decrypt
//! - If your wallet uses a complex miniscript policy like "Either 2 keys OR (a timelock AND another key)",
//!   the encryption follows this same logical structure
//!
//! ## How It Works
//!
//! The encryption mechanism works through several key innovations:
//!
//! 1. **Security Mirroring**: The descriptor's spending policy is analyzed and transformed into an
//!    equivalent encryption policy
//! 2. **Recursive Secret Sharing**: Shamir's Secret Sharing is applied recursively to split
//!    encryption keys following the script's threshold requirements
//! 3. **Per-Key Encryption**: Each share is encrypted with the corresponding public key from
//!    the descriptor, ensuring only key holders can access them
//! 4. **Compact Encoding**: Tag-based and LEB128 variable-length encoding is used to minimize the size
//     of the encrypted data
//! 5. **Payload Extraction**: Sensitive data, including the master fingerprints, public keys and xpubs,
//     hashes, and timelocks, are extracted from the descriptor and encrypted
//! 6. **Template Extraction**: The descriptor template and derivation paths remain visible in plaintext,
//!    allowing key holders to derive the necessary public keys and recover the full descriptor
//!
//! ## Examples
//!
//! ### Encrypting a Descriptor
//!
//! ```rust
//! use std::str::FromStr;
//! use descriptor_encrypt::{encrypt, decrypt};
//! use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
//!
//! // Create a descriptor - a 2-of-3 multisig in this example
//! let desc_str = "wsh(multi(2,\
//!     03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,\
//!     036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,\
//!     02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29\
//! ))";
//! let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
//!
//! // Encrypt the descriptor
//! let encrypted_data = encrypt(descriptor.clone()).unwrap();
//!
//! // Later, decrypt with the keys (in this example, only the first two keys are provided,
//! // which is sufficient for a 2-of-3 multisig)
//! let pk0 = DescriptorPublicKey::from_str("03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7").unwrap();
//! let pk1 = DescriptorPublicKey::from_str("036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00").unwrap();
//! let first_two_keys = vec![pk0, pk1];
//!
//! // Recover the original descriptor
//! let recovered_descriptor = decrypt(&encrypted_data, first_two_keys).unwrap();
//! assert_eq!(descriptor.to_string(), recovered_descriptor.to_string());
//! ```
//!
//! ### Getting Template and Derivation Paths
//!
//! ```rust,ignore
//! use descriptor_encrypt::{encrypt, get_template, get_origin_derivation_paths};
//! // (imports and setup as in previous example)
//!
//! let encrypted_data = encrypt(descriptor.clone()).unwrap();
//!
//! // Get a template descriptor with dummy keys (useful for analysis without revealing actual keys)
//! let template = get_template(&encrypted_data).unwrap();
//!
//! // Extract only the derivation paths (useful for watch-only wallets)
//! let paths = get_origin_derivation_paths(&encrypted_data).unwrap();
//! ```
//!
//! ## Supported Descriptor Types
//!
//! The library supports all standard Bitcoin descriptor types:
//!
//! - Single-signature (`pkh`, `wpkh`, `tr` with internal key)
//! - Multi-signature (`sh(multi)`, `wsh(multi)`, `sh(wsh(multi))`, etc.)
//! - Taproot (`tr` with script trees)
//! - Full Miniscript expressions (all logical operations, timelocks, hashlocks, etc.)
//! - Nested combinations of the above
//!
//! ## Security Considerations
//!
//! This library ensures:
//!
//! - Only key holders can decrypt descriptors, following the descriptor's original threshold logic
//! - Encrypted data reveals nothing about the keys or spending conditions without decryption
//! - Structure template extraction is possible without exposing sensitive information
//! - The encryption is deterministic, producing the same output given the same descriptor
//!
//! The security of the system relies on the security of ChaCha20-Poly1305 for encryption and
//! Shamir's Secret Sharing for threshold access control.
//!

// Coding conventions
#![deny(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

#[cfg(not(any(feature = "std")))]
compile_error!("`std` must be enabled");

pub use bitcoin;
pub use miniscript;

mod payload;
mod template;

use anyhow::{Result, anyhow};
use bitcoin::bip32::DerivationPath;
use miniscript::{Descriptor, DescriptorPublicKey};
use sha2::{Digest, Sha256};

use crate::payload::ToDescriptorTree;

const V0: u8 = 0u8;

/// Encrypts a descriptor such that it can only be recovered by a set of
/// keys with access to the funds.
pub fn encrypt(desc: Descriptor<DescriptorPublicKey>) -> Result<Vec<u8>> {
    let (template, payload) = template::encode(desc.clone());

    // Deterministically derive encryption key
    let mut hasher = Sha256::new();
    hasher.update(&template);
    hasher.update(&payload);
    let encryption_key = hasher.finalize();

    // Encrypt payload and shard encryption key into encrypted shares (1 per key)
    let nonce = [0u8; 12];
    let (encrypted_shares, encrypted_payload) =
        payload::encrypt_payload_and_shard_key(desc, encryption_key.into(), nonce, payload)?;

    Ok([
        vec![V0],
        template,
        encrypted_shares.concat(),
        encrypted_payload,
    ]
    .concat())
}

/// Decrypts an encrypted descriptor using a set of public keys with access to the funds
pub fn decrypt(
    data: &[u8],
    pks: Vec<DescriptorPublicKey>,
) -> Result<Descriptor<DescriptorPublicKey>> {
    if data.is_empty() {
        return Err(anyhow!("Empty data"));
    }

    let data = match data[0] {
        V0 => &data[1..],
        _ => return Err(anyhow!("Unsupported version: {}", data[0])),
    };

    let (template, size) = template::decode(data)?;

    let num_keys = template.clone().to_tree().extract_keys().len();
    let encrypted_shares: Vec<[u8; 48]> = data[size..size + num_keys * 48]
        .chunks_exact(48)
        .map(|chunk| chunk.try_into().unwrap())
        .collect();

    let encrypted_payload = &data[size + num_keys * 48..];

    let nonce = [0u8; 12];
    let payload = payload::recover_key_and_decrypt_payload(
        template.clone(),
        encrypted_shares,
        pks,
        nonce,
        encrypted_payload.to_vec(),
    )?;

    let desc = template::decode_with_payload(data, &payload)?;

    Ok(desc)
}

/// Returns a template with dummy keys, hashes, and timelocks
pub fn get_template(data: &[u8]) -> Result<Descriptor<DescriptorPublicKey>> {
    if data.is_empty() {
        return Err(anyhow!("Empty data"));
    }

    let data = match data[0] {
        V0 => &data[1..],
        _ => return Err(anyhow!("Unsupported version: {}", data[0])),
    };

    let (template, _) = template::decode(data)?;

    Ok(template)
}

/// Returns the origin derivation paths in the descriptor
pub fn get_origin_derivation_paths(data: &[u8]) -> Result<Vec<DerivationPath>> {
    if data.is_empty() {
        return Err(anyhow!("Empty data"));
    }

    let data = match data[0] {
        V0 => &data[1..],
        _ => return Err(anyhow!("Unsupported version: {}", data[0])),
    };

    let (template, _) = template::decode(data)?;

    let mut paths = Vec::new();
    for key in template.clone().to_tree().extract_keys() {
        let origin = match key {
            DescriptorPublicKey::XPub(xpub) => xpub.origin,
            DescriptorPublicKey::MultiXPub(xpub) => xpub.origin,
            DescriptorPublicKey::Single(single) => single.origin,
        };

        if let Some((_, path)) = origin {
            paths.push(path);
        }
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::ToDescriptorTree;
    use miniscript::{Descriptor, DescriptorPublicKey};
    use std::str::FromStr;

    #[test]
    fn test_integration() {
        let descriptors = vec![
            "sh(sortedmulti(2,[2c49202a/45h/0h/0h/0]xpub6EigxozzGaNVWUwEFnbyX6oHPdpWTKgJgbfpRbAcdiGpGMrdpPinCoHBXehu35sqJHpgLDTxigAnFQG3opKjXQoSmGMrMNHz81ALZSBRCWw/0/*,[55b43a50/45h/0h/0h/0]xpub6EAtA5XJ6pwFQ7L32iAJMgiWQEcrwU75NNWQ6H6eavwznDFeGFzTbSFdDKNdbG2HQdZvzrXuCyEYSSJ4cGsmfoPkKUKQ6haNKMRqG4pD4xi/0/*,[35931b5e/0/0/0/0]xpub6EDykLBC5EfaDNC7Mpg2H8veCaJHDgxH2JQvRtxJrbyeAhXWV2jJzB9XL4jMiFN5TzQefYi4V4nDiH4bxhkrweQ3Smxc8uP4ux9HrMGV81P/0/*))#eqwew7sv",
            "wsh(sortedmulti(2,[3abf21c8/48h/0h/0h/2h]xpub6DYotmPf2kXFYhJMFDpfydjiXG1RzmH1V7Fnn2Z38DgN2oSYruczMyTFZZPz6yXq47Re8anhXWGj4yMzPTA3bjPDdpA96TLUbMehrH3sBna/<0;1>/*,[a1a4bd46/48h/0h/0h/2h]xpub6DvXYo8BwnRACos42ME7tNL48JQhLMQ33ENfniLM9KZmeZGbBhyh1Jkfo3hUKmmjW92o3r7BprTPPdrTr4QLQR7aRnSBfz1UFMceW5ibhTc/<0;1>/*,[ed91913d/48h/0h/0h/2h]xpub6EQUho4Z4pwh2UQGdPjoPrbtjd6qqseKZCEBLcZbJ7y6c9XBWHRkhERiADJfwRcUs14nQsxF3hvx7aFkbk3tfp4dnKfkcns217kBTVVN5gY/<0;1>/*))#hpcyqx44",
            "sh(wsh(sortedmulti(2,[2c49202a/45h/0h/0h/0]xpub6EigxozzGaNVWUwEFnbyX6oHPdpWTKgJgbfpRbAcdiGpGMrdpPinCoHBXehu35sqJHpgLDTxigAnFQG3opKjXQoSmGMrMNHz81ALZSBRCWw/0/*,[55b43a50/45h/0h/0h/0]xpub6EAtA5XJ6pwFQ7L32iAJMgiWQEcrwU75NNWQ6H6eavwznDFeGFzTbSFdDKNdbG2HQdZvzrXuCyEYSSJ4cGsmfoPkKUKQ6haNKMRqG4pD4xi/0/*,[35931b5e/0/0/0/0]xpub6EDykLBC5EfaDNC7Mpg2H8veCaJHDgxH2JQvRtxJrbyeAhXWV2jJzB9XL4jMiFN5TzQefYi4V4nDiH4bxhkrweQ3Smxc8uP4ux9HrMGV81P/0/*)))#xsfvldas",
            "wsh(multi(2,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,023e9be8b82c7469c88b1912a61611dffb9f65bbf5a176952727e0046513eca0de))",
            "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)",
            "sh(wsh(or_d(pk(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),and_v(v:pk(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),older(1000)))))",
            "wsh(thresh(4,pk([7258e4f9/44h/1h/0h]tpubDCZrkQoEU3845aFKUu9VQBYWZtrTwxMzcxnBwKFCYXHD6gEXvtFcxddCCLFsEwmxQaG15izcHxj48SXg1QS5FQGMBx5Ak6deXKPAL7wauBU/0/*),s:pk([c80b1469/44h/1h/0h]tpubDD3UwwHoNUF4F3Vi5PiUVTc3ji1uThuRfFyBexTSHoAcHuWW2z8qEE2YujegcLtgthr3wMp3ZauvNG9eT9xfJyxXCfNty8h6rDBYU8UU1qq/0/*),s:pk([4e5024fe/44h/1h/0h]tpubDDLrpPymPLSCJyCMLQdmcWxrAWwsqqssm5NdxT2WSdEBPSXNXxwbeKtsHAyXPpLkhUyKovtZgCi47QxVpw9iVkg95UUgeevyAqtJ9dqBqa1/0/*),s:pk([3b1d1ee9/44h/1h/0h]tpubDCmDTANBWPzf6d8Ap1J5Ku7J1Ay92MpHMrEV7M5muWxCrTBN1g5f1NPcjMEL6dJHxbvEKNZtYCdowaSTN81DAyLsmv6w6xjJHCQNkxrsrfu/0/*),sln:after(840000),sln:after(1050000),sln:after(1260000)))#k28080kv",
            "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)})",
        ];

        for desc_str in descriptors {
            let desc = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();

            let keys = desc.clone().to_tree().extract_keys();
            let ciphertext = encrypt(desc.clone()).unwrap();
            assert_eq!(desc, decrypt(&ciphertext, keys).unwrap());
        }
    }

    #[test]
    fn test_unsupported_version() {
        let desc_str = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
        let desc = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();

        // Modify the version byte to an invalid version
        let mut encrypted_data = encrypt(desc.clone()).unwrap();
        encrypted_data[0] = 0xFF;

        let template_result = get_template(&encrypted_data);
        assert!(
            template_result
                .unwrap_err()
                .to_string()
                .contains("Unsupported version: 255")
        );

        let paths_result = get_origin_derivation_paths(&encrypted_data);
        assert!(
            paths_result
                .unwrap_err()
                .to_string()
                .contains("Unsupported version: 255")
        );

        let key = DescriptorPublicKey::from_str(
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        )
        .unwrap();

        let decrypt_result = decrypt(&encrypted_data, vec![key]);
        assert!(
            decrypt_result
                .unwrap_err()
                .to_string()
                .contains("Unsupported version: 255")
        );
    }

    #[test]
    fn test_empty() {
        let empty_data: Vec<u8> = vec![];

        let template_result = get_template(&empty_data);
        assert!(
            template_result
                .unwrap_err()
                .to_string()
                .contains("Empty data")
        );

        let paths_result = get_origin_derivation_paths(&empty_data);
        assert!(paths_result.unwrap_err().to_string().contains("Empty data"));

        let decrypt_result = decrypt(
            &empty_data,
            vec![
                DescriptorPublicKey::from_str(
                    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                )
                .unwrap(),
            ],
        );
        assert!(
            decrypt_result
                .unwrap_err()
                .to_string()
                .contains("Empty data")
        );
    }
}
