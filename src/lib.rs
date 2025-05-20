// Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// SPDX-License-Identifier: CC0-1.0

//! Descriptor Encrypt
//!
//! ## Overview
//! This project implements a system that lets any Bitcoin wallet descriptor 
//! be efficiently encrypted such that only a set of keys that can spend the
//! funds can recover the descriptor.
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

use anyhow::Result;
use bitcoin::bip32::DerivationPath;
use miniscript::{Descriptor, DescriptorPublicKey};
use sha2::{Digest, Sha256};

use crate::payload::ToDescriptorNode;

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

    Ok([template, encrypted_shares.concat(), encrypted_payload].concat())
}

/// Decrypts an encrypted descriptor using a set of public keys with access to the funds
pub fn decrypt(
    data: &[u8],
    pks: Vec<DescriptorPublicKey>,
) -> Result<Descriptor<DescriptorPublicKey>> {
    let (template, size) = template::decode(data)?;

    let num_keys = template.clone().to_node().extract_keys().len();
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
    let (template, _) = template::decode(data)?;

    Ok(template)
}

/// Returns the origin derivation paths in the descriptor
pub fn get_origin_derivation_paths(data: &[u8]) -> Result<Vec<DerivationPath>> {
    let (template, _) = template::decode(data)?;

    let mut paths = Vec::new();
    for key in template.clone().to_node().extract_keys() {
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

            let keys = desc.clone().to_node().extract_keys();
            let ciphertext = encrypt(desc.clone()).unwrap();
            assert_eq!(desc, decrypt(&ciphertext, keys).unwrap());
        }
    }
}
