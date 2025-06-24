//! Tagging Fingerprints
//!
//! Generate a four-byte hash of a set of fingerprints corresponding to seeds
//! that can be used to decrypt.

use bitcoin::bip32::Fingerprint;
use miniscript::DescriptorPublicKey;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Number of bytes in a tag
pub const TAG_SIZE: usize = 4;

/// A four-byte hash of a set of fingerprints
pub type Tag = [u8; TAG_SIZE];

/// Returns a deterministic four-byte hash for a set of fingerprints.
///
/// Return None if set is empty.
pub fn compute_tag(fps: Vec<Fingerprint>) -> Option<Tag> {
    if fps.is_empty() {
        return None;
    }

    let mut deduped: Vec<_> = HashSet::<Fingerprint>::from_iter(fps).into_iter().collect();
    deduped.sort_unstable();

    let mut hasher = Sha256::new();
    for fp in deduped {
        hasher.update(&fp[..]);
    }

    let hash = hasher.finalize();
    let mut result = [0u8; TAG_SIZE];
    result.copy_from_slice(&hash[..TAG_SIZE]);
    Some(result)
}

/// Returns a four-byte tag for a set of keys using their origin master fingerprints.
///
/// Return None if no origin master fingerprints exist.
pub fn compute_tag_from_origins(pks: Vec<DescriptorPublicKey>) -> Option<Tag> {
    let fps: Vec<Fingerprint> = pks
        .iter()
        .filter_map(|pk| origin_master_fingerprint(pk))
        .collect();

    compute_tag(fps)
}

/// Returns the key's (optional) origin master fingerprint.
fn origin_master_fingerprint(pk: &DescriptorPublicKey) -> Option<Fingerprint> {
    let origin = match pk {
        DescriptorPublicKey::XPub(xpub) => &xpub.origin,
        DescriptorPublicKey::MultiXPub(xpub) => &xpub.origin,
        DescriptorPublicKey::Single(single) => &single.origin,
    };

    if let Some((fingerprint, _)) = origin {
        Some(*fingerprint)
    } else {
        None
    }
}
