// SPDX-License-Identifier: CC0-1.0

use bitcoin::bip32::Fingerprint;
use miniscript::DescriptorPublicKey;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Number of bytes in a tag
pub const TAG_SIZE: usize = 4;

/// Returns a unique deterministic tag for this set of keys based on their origin master fingerprints.
///
/// Return None if no origin master fingerprints are found.
pub fn tag(pks: &[DescriptorPublicKey]) -> Option<[u8; TAG_SIZE]> {
    let fps: Vec<Fingerprint> = pks
        .iter()
        .filter_map(|pk| origin_master_fingerprint(pk))
        .collect();

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
