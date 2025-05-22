use anyhow::Result;
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
use miniscript::descriptor::{DescriptorPublicKey, SinglePubKey};
use sha2::{Digest, Sha256};

/// A trait to construct a cipher that encrypts using a public key
pub trait KeyCipher {
    /// Returns ciphertext encrypted using a public key, a derivation hash, and an index
    fn encrypt(
        &self,
        plaintext: Vec<u8>,
        pk: &DescriptorPublicKey,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>>;

    /// Returns plaintext decrypted from ciphertext using a set of public keys, a derivation hash, and an index
    fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        pks: &Vec<DescriptorPublicKey>,
        hash: &[u8; 32],
        index: usize,
    ) -> Option<Vec<u8>>;
}

pub struct AuthenticatedCipher {}

impl KeyCipher for AuthenticatedCipher {
    fn encrypt(
        &self,
        plaintext: Vec<u8>,
        pk: &DescriptorPublicKey,
        hash: &[u8; 32],
        index: usize,
    ) -> Result<Vec<u8>> {
        let (nonce, cipher) = get_chacha20_poly1305_cipher(pk, hash, index)?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 encryption error: {:?}", e))?;

        Ok(ciphertext.as_slice().try_into().unwrap())
    }

    fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        pks: &Vec<DescriptorPublicKey>,
        hash: &[u8; 32],
        index: usize,
    ) -> Option<Vec<u8>> {
        for pk in pks {
            let Ok((nonce, cipher)) = get_chacha20_poly1305_cipher(pk, hash, index) else {
                continue;
            };
            let Ok(result) = cipher.decrypt(&nonce, ciphertext.as_ref()) else {
                continue;
            };

            return Some(result);
        }

        None
    }
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
