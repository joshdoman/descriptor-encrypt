// SPDX-License-Identifier: CC0-1.0

use miniscript::{
    Legacy, Miniscript, MiniscriptKey, ScriptContext, Segwitv0, Threshold,
    descriptor::{Descriptor, Sh, ShInner, SortedMultiVec, Tr, Wsh, WshInner},
    miniscript::decode::Terminal,
};

type DescriptorTreeThreshold<Pk> = Threshold<DescriptorTree<Pk>, 0>;
type KeylessDescriptorTreeThreshold<Pk> = Threshold<KeylessDescriptorTree<Pk>, 0>;

/// A tree can be keyless, a key, or a threshold of trees
#[derive(Clone, Debug)]
pub enum DescriptorTree<Pk: MiniscriptKey> {
    /// A keyless tree that can be either satisfiable or unsatisfiable
    Keyless(bool),
    /// A key
    Key(Pk),
    /// A threshold of trees
    Threshold(DescriptorTreeThreshold<Pk>),
}

/// A tree can a key, or a threshold of trees
#[derive(Clone, Debug)]
pub enum KeylessDescriptorTree<Pk: MiniscriptKey> {
    /// A key
    Key(Pk),
    /// A threshold of trees
    Threshold(KeylessDescriptorTreeThreshold<Pk>),
}

impl<Pk: MiniscriptKey> DescriptorTree<Pk> {
    /// Returns a list of keys in the descriptor
    pub fn extract_keys(&self) -> Vec<Pk> {
        match self {
            DescriptorTree::Keyless(_) => Vec::new(),
            DescriptorTree::Key(pk) => vec![pk.clone()],
            DescriptorTree::Threshold(thresh) => {
                thresh.iter().flat_map(|tree| tree.extract_keys()).collect()
            }
        }
    }

    /// Prune keyless trees assuming they evaluate to `true`.
    /// Sets new_k = max(old_k - num(keyless), 0) in each threshold.
    pub fn prune_keyless(&self) -> Option<KeylessDescriptorTree<Pk>> {
        let (_, pruned_tree) = self.prune_keyless_with_satisfiability();
        pruned_tree
    }

    // Returns pruned tree and whether its satisfiable
    pub fn prune_keyless_with_satisfiability(&self) -> (bool, Option<KeylessDescriptorTree<Pk>>) {
        match self {
            DescriptorTree::Keyless(satisfiable) => (*satisfiable, None),
            DescriptorTree::Key(pk) => (true, Some(KeylessDescriptorTree::Key(pk.clone()))),
            DescriptorTree::Threshold(thresh) => {
                let mut assume_satisfied = 0;
                let mut keyed_subtrees = Vec::new();
                for t in thresh.iter() {
                    match t.prune_keyless_with_satisfiability() {
                        (_, Some(subtree)) => {
                            keyed_subtrees.push(subtree);
                        }
                        (true, None) => assume_satisfied += 1,
                        (false, None) => {},
                    }
                }

                let new_k = if thresh.k() > assume_satisfied {
                    thresh.k() - assume_satisfied
                } else {
                    0
                };

                match (new_k, keyed_subtrees.len()) {
                    (0, _) => (true, None),
                    (1, 1) => (true, Some(keyed_subtrees.first().unwrap().clone())),
                    (k, n) => {
                        if k <= n {
                            (true, KeylessDescriptorTreeThreshold::new(new_k, keyed_subtrees)
                            .ok()
                            .map(KeylessDescriptorTree::Threshold))
                        } else {
                            (false, None)
                        }
                    }
                }
            }
        }
    }

    fn from_ms_and<Ctx>(ms0: &Miniscript<Pk, Ctx>, ms1: &Miniscript<Pk, Ctx>) -> Self
    where
        Ctx: ScriptContext,
    {
        let tree0 = ms0.to_tree();
        let tree1 = ms1.to_tree();
        let thresh = DescriptorTreeThreshold::and(tree0, tree1);

        DescriptorTree::Threshold(thresh)
    }

    fn from_ms_or<Ctx>(ms0: &Miniscript<Pk, Ctx>, ms1: &Miniscript<Pk, Ctx>) -> Self
    where
        Ctx: ScriptContext,
    {
        let tree0 = ms0.to_tree();
        let tree1 = ms1.to_tree();
        let thresh = DescriptorTreeThreshold::or(tree0, tree1);

        DescriptorTree::Threshold(thresh)
    }

    fn from_sortedmulti<Ctx>(sortedmulti: &SortedMultiVec<Pk, Ctx>) -> Self
    where
        Ctx: ScriptContext,
    {
        let trees = sortedmulti
            .pks()
            .iter()
            .map(|pk| DescriptorTree::Key(pk.clone()))
            .collect();
        let thresh = DescriptorTreeThreshold::new(sortedmulti.k(), trees).unwrap();

        DescriptorTree::Threshold(thresh)
    }
}

/// A trait to construct a descriptor tree
pub trait ToDescriptorTree<Pk: MiniscriptKey> {
    /// Returns a descriptor tree
    fn to_tree(&self) -> DescriptorTree<Pk>;
}

impl<Pk: MiniscriptKey> ToDescriptorTree<Pk> for Descriptor<Pk> {
    fn to_tree(&self) -> DescriptorTree<Pk> {
        match self {
            Descriptor::Sh(sh) => sh.to_tree(),
            Descriptor::Wsh(wsh) => wsh.to_tree(),
            Descriptor::Tr(tr) => tr.to_tree(),
            Descriptor::Wpkh(wpkh) => DescriptorTree::Key(wpkh.clone().into_inner()),
            Descriptor::Pkh(pkh) => DescriptorTree::Key(pkh.clone().into_inner()),
            Descriptor::Bare(bare) => bare.as_inner().to_tree(),
        }
    }
}

impl<Pk: MiniscriptKey> ToDescriptorTree<Pk> for Sh<Pk> {
    fn to_tree(&self) -> DescriptorTree<Pk> {
        match self.as_inner() {
            ShInner::SortedMulti(sortedmulti) => {
                DescriptorTree::from_sortedmulti::<Legacy>(&sortedmulti)
            }
            ShInner::Wsh(wsh) => wsh.to_tree(),
            ShInner::Wpkh(wpkh) => DescriptorTree::Key(wpkh.clone().into_inner()),
            ShInner::Ms(ms) => ms.to_tree(),
        }
    }
}

impl<Pk: MiniscriptKey> ToDescriptorTree<Pk> for Wsh<Pk> {
    fn to_tree(&self) -> DescriptorTree<Pk> {
        match self.as_inner() {
            WshInner::SortedMulti(sortedmulti) => {
                DescriptorTree::from_sortedmulti::<Segwitv0>(&sortedmulti)
            }
            WshInner::Ms(ms) => ms.to_tree(),
        }
    }
}

impl<Pk: MiniscriptKey> ToDescriptorTree<Pk> for Tr<Pk> {
    fn to_tree(&self) -> DescriptorTree<Pk> {
        let mut trees = Vec::new();
        trees.push(DescriptorTree::Key(self.internal_key().clone()));

        for (_, ms) in self.iter_scripts() {
            trees.push(ms.to_tree());
        }

        let thresh = DescriptorTreeThreshold::or_n(trees);

        DescriptorTree::Threshold(thresh)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> ToDescriptorTree<Pk> for Miniscript<Pk, Ctx> {
    fn to_tree(&self) -> DescriptorTree<Pk> {
        match &self.node {
            Terminal::True => DescriptorTree::Keyless(true),
            Terminal::False => DescriptorTree::Keyless(false),
            Terminal::PkK(pk) => DescriptorTree::Key(pk.clone()),
            Terminal::PkH(pk) => DescriptorTree::Key(pk.clone()),
            Terminal::RawPkH(_) => DescriptorTree::Keyless(true),
            Terminal::After(_) => DescriptorTree::Keyless(true),
            Terminal::Older(_) => DescriptorTree::Keyless(true),
            Terminal::Sha256(_) => DescriptorTree::Keyless(true),
            Terminal::Hash256(_) => DescriptorTree::Keyless(true),
            Terminal::Ripemd160(_) => DescriptorTree::Keyless(true),
            Terminal::Hash160(_) => DescriptorTree::Keyless(true),
            Terminal::Alt(ms) => ms.to_tree(),
            Terminal::Swap(ms) => ms.to_tree(),
            Terminal::Check(ms) => ms.to_tree(),
            Terminal::DupIf(ms) => ms.to_tree(),
            Terminal::Verify(ms) => ms.to_tree(),
            Terminal::NonZero(ms) => ms.to_tree(),
            Terminal::ZeroNotEqual(ms) => ms.to_tree(),
            Terminal::AndV(ms0, ms1) => DescriptorTree::from_ms_and(ms0, ms1),
            Terminal::AndB(ms0, ms1) => DescriptorTree::from_ms_and(ms0, ms1),
            Terminal::AndOr(ms0, ms1, ms2) => {
                let and_tree = DescriptorTree::from_ms_and(ms0, ms1);
                let or_tree = ms2.to_tree();
                let thresh = DescriptorTreeThreshold::or(and_tree, or_tree);

                DescriptorTree::Threshold(thresh)
            }
            Terminal::OrB(ms0, ms1) => DescriptorTree::from_ms_or(ms0, ms1),
            Terminal::OrC(ms0, ms1) => DescriptorTree::from_ms_or(ms0, ms1),
            Terminal::OrD(ms0, ms1) => DescriptorTree::from_ms_or(ms0, ms1),
            Terminal::OrI(ms0, ms1) => DescriptorTree::from_ms_or(ms0, ms1),
            Terminal::Thresh(thresh) => {
                let mut trees = Vec::new();
                for ms in thresh.iter() {
                    let tree = ms.to_tree();
                    trees.push(tree);
                }
                let thresh = DescriptorTreeThreshold::new(thresh.k(), trees).unwrap();

                DescriptorTree::Threshold(thresh)
            }
            Terminal::Multi(thresh) => {
                let trees = thresh
                    .iter()
                    .map(|pk| DescriptorTree::Key(pk.clone()))
                    .collect();
                let thresh = DescriptorTreeThreshold::new(thresh.k(), trees).unwrap();

                DescriptorTree::Threshold(thresh)
            }
            Terminal::MultiA(thresh) => {
                let trees = thresh
                    .iter()
                    .map(|pk| DescriptorTree::Key(pk.clone()))
                    .collect();
                let thresh = DescriptorTreeThreshold::new(thresh.k(), trees).unwrap();

                DescriptorTree::Threshold(thresh)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1;
    use miniscript::descriptor::DescriptorPublicKey;
    use std::str::FromStr;

    // Helper function to create test keys
    fn create_test_key(index: u32) -> DescriptorPublicKey {
        let secp = secp256k1::Secp256k1::new();
        let secret_value = 1u32 + index;

        let mut sk = [0u8; 32];
        sk[28..32].copy_from_slice(&secret_value.to_be_bytes());

        let pubkey = bitcoin::PublicKey {
            inner: secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&sk).expect("sk"),
            ),
            compressed: true,
        };

        DescriptorPublicKey::Single(miniscript::descriptor::SinglePub {
            key: miniscript::descriptor::SinglePubKey::FullKey(pubkey),
            origin: None,
        })
    }

    #[test]
    fn test_extract_keys_single() {
        // Test with a single key
        let key = create_test_key(1);
        let tree = DescriptorTree::Key(key.clone());

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&key));
    }

    #[test]
    fn test_extract_keys_threshold() {
        // Create a 2-of-3 threshold
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        let trees = vec![
            DescriptorTree::Key(key1.clone()),
            DescriptorTree::Key(key2.clone()),
            DescriptorTree::Key(key3.clone()),
        ];

        let thresh = DescriptorTreeThreshold::new(2, trees).unwrap();
        let tree = DescriptorTree::Threshold(thresh);

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&key1));
        assert!(keys.contains(&key2));
        assert!(keys.contains(&key3));
    }

    #[test]
    fn test_extract_keys_with_keyless() {
        // Create a threshold with some keyless trees
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        let trees = vec![
            DescriptorTree::Key(key1.clone()),
            DescriptorTree::Keyless::<DescriptorPublicKey>(true),
            DescriptorTree::Key(key2.clone()),
        ];

        let thresh = DescriptorTreeThreshold::new(2, trees).unwrap();
        let tree = DescriptorTree::Threshold(thresh);

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&key1));
        assert!(keys.contains(&key2));
    }

    #[test]
    fn test_prune_keyless_single() {
        // Key trees should remain unchanged
        let key = create_test_key(1);
        let tree = DescriptorTree::Key(key.clone());

        let result = tree.prune_keyless();
        assert!(result.is_some());

        match result.unwrap() {
            KeylessDescriptorTree::Key(k) => assert_eq!(k, key),
            _ => panic!("Expected Key tree"),
        }

        // Keyless trees should return None
        let tree = DescriptorTree::Keyless::<DescriptorPublicKey>(true);
        let result = tree.prune_keyless();
        assert!(result.is_none());
    }

    #[test]
    fn test_prune_keyless_threshold() {
        // Create a 2-of-3 threshold with one keyless tree
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        let trees = vec![
            DescriptorTree::Key(key1.clone()),
            DescriptorTree::Keyless::<DescriptorPublicKey>(true),
            DescriptorTree::Keyless::<DescriptorPublicKey>(false),
            DescriptorTree::Key(key2.clone()),
        ];

        let thresh = DescriptorTreeThreshold::new(2, trees).unwrap();
        let tree = DescriptorTree::Threshold(thresh);

        let result = tree.prune_keyless();
        assert!(result.is_some());

        match result.unwrap() {
            KeylessDescriptorTree::Threshold(t) => {
                assert_eq!(t.k(), 1);
                assert_eq!(t.n(), 2);

                // Check that the keys are the same
                let mut keys = Vec::new();
                for subtree in t.iter() {
                    match subtree {
                        KeylessDescriptorTree::Key(pk) => keys.push(pk.clone()),
                        _ => {}
                    }
                }
                assert!(keys.contains(&key1));
                assert!(keys.contains(&key2));
            }
            _ => panic!("Expected Threshold tree"),
        }
    }

    #[test]
    fn test_prune_keyless_reduce_threshold() {
        // Test that k gets reduced to n if needed
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        let trees = vec![
            DescriptorTree::Key(key1.clone()),
            DescriptorTree::Keyless::<DescriptorPublicKey>(true),
            DescriptorTree::Keyless::<DescriptorPublicKey>(true),
            DescriptorTree::Keyless::<DescriptorPublicKey>(false),
            DescriptorTree::Key(key2.clone()),
        ];

        let thresh = DescriptorTreeThreshold::new(3, trees).unwrap();
        let tree = DescriptorTree::Threshold(thresh);

        let result = tree.prune_keyless();
        assert!(result.is_some());

        match result.unwrap() {
            KeylessDescriptorTree::Threshold(t) => {
                assert_eq!(t.k(), 1); // Reduced from 3 to 1
                assert_eq!(t.n(), 2);

                // Check that the keys are the same
                let mut keys = Vec::new();
                for subtree in t.iter() {
                    match subtree {
                        KeylessDescriptorTree::Key(pk) => keys.push(pk.clone()),
                        _ => {}
                    }
                }
                assert!(keys.contains(&key1));
                assert!(keys.contains(&key2));
            }
            _ => panic!("Expected Threshold tree"),
        }
    }

    #[test]
    fn test_prune_keyless_all_trees_keyless() {
        // Test a scenario where all trees are keyless
        let trees = vec![
            DescriptorTree::Keyless::<DescriptorPublicKey>(true),
            DescriptorTree::Keyless::<DescriptorPublicKey>(true),
        ];

        let thresh = DescriptorTreeThreshold::new(1, trees).unwrap();
        let tree = DescriptorTree::Threshold(thresh);

        let result = tree.prune_keyless();
        assert!(result.is_none());
    }

    #[test]
    fn test_prune_keyless_k_exceeds_n_due_to_unsatisfiability() {
        let key1 = create_test_key(1);

        // Test tree with satisfiable pruned leaf
        let trees = vec![
            DescriptorTree::Key(key1.clone()),
            DescriptorTree::Keyless::<DescriptorPublicKey>(true),
        ];

        let thresh = DescriptorTreeThreshold::new(2, trees).unwrap();
        let tree = DescriptorTree::Threshold(thresh);

        let result = tree.prune_keyless();
        assert!(result.is_some());

        // Test tree with unsatisfiable pruned leaf
        let trees = vec![
            DescriptorTree::Key(key1.clone()),
            DescriptorTree::Keyless::<DescriptorPublicKey>(false),
        ];

        let thresh = DescriptorTreeThreshold::new(2, trees).unwrap();
        let tree = DescriptorTree::Threshold(thresh);

        let result = tree.prune_keyless();
        assert!(result.is_none());
    }

    #[test]
    fn test_prune_keyless_single_key_after_pruning() {
        // Create a threshold with one key and one keyless tree
        let key = create_test_key(1);

        let trees = vec![
            DescriptorTree::Key(key.clone()),
            DescriptorTree::Keyless::<DescriptorPublicKey>(true),
        ];

        let thresh = DescriptorTreeThreshold::new(2, trees).unwrap();
        let tree = DescriptorTree::Threshold(thresh);

        let result = tree.prune_keyless();
        assert!(result.is_some());

        // After pruning, we should be left with just the key tree
        match result.unwrap() {
            KeylessDescriptorTree::Key(k) => assert_eq!(k, key),
            _ => panic!("Expected a single Key tree"),
        }
    }

    #[test]
    fn test_to_tree_wpkh() {
        // Test WPKH descriptor
        let key = create_test_key(1);
        let desc_str = format!("wpkh({})", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        // Should be a single key tree
        match tree {
            DescriptorTree::Key(k) => match (k, key) {
                (
                    DescriptorPublicKey::Single(single_k),
                    DescriptorPublicKey::Single(single_key),
                ) => match (&single_k.key, &single_key.key) {
                    (
                        miniscript::descriptor::SinglePubKey::FullKey(k_pk),
                        miniscript::descriptor::SinglePubKey::FullKey(key_pk),
                    ) => {
                        assert_eq!(k_pk.inner.serialize(), key_pk.inner.serialize());
                    }
                    _ => panic!("Expected FullKey for both keys"),
                },
                _ => panic!("Expected Single keys"),
            },
            _ => panic!("Expected Key tree for wpkh descriptor"),
        }
    }

    #[test]
    fn test_to_tree_pkh() {
        // Test PKH descriptor
        let key = create_test_key(1);
        let desc_str = format!("pkh({})", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        // Should be a single key tree
        match tree {
            DescriptorTree::Key(_) => {}
            _ => panic!("Expected Key tree for pkh descriptor"),
        }
    }

    #[test]
    fn test_to_tree_bare_pk() {
        let desc_str = "pk(020000000000000000000000000000000000000000000000000000000000000002)";
        let desc = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();

        let tree = desc.to_tree();

        // Should be a single key tree
        match tree {
            DescriptorTree::Key(_) => {}
            _ => panic!("Expected Key tree for pkh descriptor"),
        }
    }

    #[test]
    fn test_to_tree_wsh_multi() {
        // Test WSH with a multisig
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        let desc_str = format!("wsh(multi(2,{},{},{}))", key1, key2, key3);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 3);

        // Should be a threshold with 3 key trees
        match tree {
            DescriptorTree::Threshold(t) => {
                assert_eq!(t.k(), 2);
                assert_eq!(t.n(), 3);

                // We can't use contains directly because we need to compare the serialized keys
                let key_serialized1 = serialize_descriptor_pubkey(&key1);
                let key_serialized2 = serialize_descriptor_pubkey(&key2);
                let key_serialized3 = serialize_descriptor_pubkey(&key3);

                let extracted_serialized: Vec<_> = keys
                    .iter()
                    .map(|k| serialize_descriptor_pubkey(k))
                    .collect();

                assert!(extracted_serialized.contains(&key_serialized1));
                assert!(extracted_serialized.contains(&key_serialized2));
                assert!(extracted_serialized.contains(&key_serialized3));
            }
            _ => panic!("Expected Threshold tree for wsh(multi) descriptor"),
        }
    }

    #[test]
    fn test_to_tree_sh_wsh_multi() {
        // Test nested SH-WSH with a multisig
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        let desc_str = format!("sh(wsh(multi(2,{},{})))", key1, key2);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 2);

        // Should be a threshold with 2 key trees
        match tree {
            DescriptorTree::Threshold(t) => {
                assert_eq!(t.k(), 2);
                assert_eq!(t.n(), 2);

                let key_serialized1 = serialize_descriptor_pubkey(&key1);
                let key_serialized2 = serialize_descriptor_pubkey(&key2);

                let extracted_serialized: Vec<_> = keys
                    .iter()
                    .map(|k| serialize_descriptor_pubkey(k))
                    .collect();

                assert!(extracted_serialized.contains(&key_serialized1));
                assert!(extracted_serialized.contains(&key_serialized2));
            }
            _ => panic!("Expected Threshold tree for sh(wsh(multi)) descriptor"),
        }
    }

    #[test]
    fn test_to_tree_tr() {
        // Test taproot descriptor with an internal key and no scripts
        let key = create_test_key(1);
        let desc_str = format!("tr({})", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 1);

        // Should be a threshold tree with just the internal key
        match tree {
            DescriptorTree::Threshold(t) => {
                assert_eq!(t.n(), 1); // Just the internal key, no scripts

                // Compare serialized keys
                let key_serialized = serialize_descriptor_pubkey(&key);
                let extracted_serialized = serialize_descriptor_pubkey(&keys[0]);
                assert_eq!(extracted_serialized, key_serialized);
            }
            _ => panic!("Expected Threshold tree for tr descriptor"),
        }
    }

    #[test]
    fn test_to_tree_tr_with_scripts() {
        // Test taproot descriptor with scripts
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        // tr with internal key and one script path spending with key2
        let desc_str = format!("tr({},pk({}))", key1, key2);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 2);

        // Should be a threshold with internal key and script key
        match tree {
            DescriptorTree::Threshold(t) => {
                assert_eq!(t.n(), 2); // Internal key + 1 script

                let key_serialized1 = serialize_descriptor_pubkey(&key1);
                let key_serialized2 = serialize_descriptor_pubkey(&key2);

                let extracted_serialized: Vec<_> = keys
                    .iter()
                    .map(|k| serialize_descriptor_pubkey(k))
                    .collect();

                assert!(extracted_serialized.contains(&key_serialized1));
                assert!(extracted_serialized.contains(&key_serialized2));
            }
            _ => panic!("Expected Threshold tree for tr descriptor with script"),
        }

        // tr with internal key and two script paths
        let desc_str = format!("tr({},{{pk({}),pk({})}})", key1, key2, key3);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 3);

        // Should be a threshold with internal key and two script keys
        match tree {
            DescriptorTree::Threshold(t) => {
                assert_eq!(t.n(), 3); // Internal key + 2 scripts

                let key_serialized1 = serialize_descriptor_pubkey(&key1);
                let key_serialized2 = serialize_descriptor_pubkey(&key2);
                let key_serialized3 = serialize_descriptor_pubkey(&key3);

                let extracted_serialized: Vec<_> = keys
                    .iter()
                    .map(|k| serialize_descriptor_pubkey(k))
                    .collect();

                assert!(extracted_serialized.contains(&key_serialized1));
                assert!(extracted_serialized.contains(&key_serialized2));
                assert!(extracted_serialized.contains(&key_serialized3));
            }
            _ => panic!("Expected Threshold tree for tr descriptor with multiple scripts"),
        }
    }

    #[test]
    fn test_to_tree_with_miniscript_and() {
        // Test a descriptor with an AND operation in miniscript
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        // wsh(and_v(v:pk(key1),pk(key2))) - requires both keys
        let desc_str = format!("wsh(and_v(v:pk({}),pk({})))", key1, key2);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 2);

        // Should be a threshold requiring all (k=n)
        match tree {
            DescriptorTree::Threshold(t) => {
                assert_eq!(t.k(), t.n()); // AND requires all keys

                let key_serialized1 = serialize_descriptor_pubkey(&key1);
                let key_serialized2 = serialize_descriptor_pubkey(&key2);

                let extracted_serialized: Vec<_> = keys
                    .iter()
                    .map(|k| serialize_descriptor_pubkey(k))
                    .collect();

                assert!(extracted_serialized.contains(&key_serialized1));
                assert!(extracted_serialized.contains(&key_serialized2));
            }
            _ => panic!("Expected Threshold tree for AND miniscript"),
        }
    }

    #[test]
    fn test_to_tree_with_miniscript_or() {
        // Test a descriptor with an OR operation in miniscript
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        // wsh(or_d(pk(key1),pk(key2))) - requires one of the keys
        let desc_str = format!("wsh(or_d(pk({}),pk({})))", key1, key2);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 2);

        // Should be a 1-of-n threshold
        match tree {
            DescriptorTree::Threshold(t) => {
                assert_eq!(t.k(), 1); // OR requires 1 of the keys
                assert_eq!(t.n(), 2);

                let key_serialized1 = serialize_descriptor_pubkey(&key1);
                let key_serialized2 = serialize_descriptor_pubkey(&key2);

                let extracted_serialized: Vec<_> = keys
                    .iter()
                    .map(|k| serialize_descriptor_pubkey(k))
                    .collect();

                assert!(extracted_serialized.contains(&key_serialized1));
                assert!(extracted_serialized.contains(&key_serialized2));
            }
            _ => panic!("Expected Threshold tree for OR miniscript"),
        }
    }

    #[test]
    fn test_to_tree_with_miniscript_thresh() {
        // Test a descriptor with a threshold operation in miniscript
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        // wsh(thresh(2,pk(key1),pk(key2),pk(key3)))
        let desc_str = format!("wsh(thresh(2,pk({}),s:pk({}),s:pk({})))", key1, key2, key3);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 3);

        // Should be a 2-of-3 threshold
        match tree {
            DescriptorTree::Threshold(t) => {
                assert_eq!(t.k(), 2);
                assert_eq!(t.n(), 3);

                let key_serialized1 = serialize_descriptor_pubkey(&key1);
                let key_serialized2 = serialize_descriptor_pubkey(&key2);
                let key_serialized3 = serialize_descriptor_pubkey(&key3);

                let extracted_serialized: Vec<_> = keys
                    .iter()
                    .map(|k| serialize_descriptor_pubkey(k))
                    .collect();

                assert!(extracted_serialized.contains(&key_serialized1));
                assert!(extracted_serialized.contains(&key_serialized2));
                assert!(extracted_serialized.contains(&key_serialized3));
            }
            _ => panic!("Expected Threshold tree for thresh miniscript"),
        }
    }

    #[test]
    fn test_to_tree_with_miniscript_andor() {
        // Test a descriptor with an AND_OR operation in miniscript
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        // wsh(andor(pk(key1),pk(key2),pk(key3)))
        // Equivalent to: (key1 AND key2) OR key3
        let desc_str = format!("wsh(andor(pk({}),pk({}),pk({})))", key1, key2, key3);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        // Extract keys and ensure all 3 keys are there
        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 3);

        let key_serialized1 = serialize_descriptor_pubkey(&key1);
        let key_serialized2 = serialize_descriptor_pubkey(&key2);
        let key_serialized3 = serialize_descriptor_pubkey(&key3);

        let extracted_serialized: Vec<_> = keys
            .iter()
            .map(|k| serialize_descriptor_pubkey(k))
            .collect();

        assert!(extracted_serialized.contains(&key_serialized1));
        assert!(extracted_serialized.contains(&key_serialized2));
        assert!(extracted_serialized.contains(&key_serialized3));
    }

    #[test]
    fn test_to_tree_with_timelock() {
        // Test a descriptor with a timelock
        let key = create_test_key(1);

        // wsh(and_v(v:pk(key),after(100)))
        let desc_str = format!("wsh(and_v(v:pk({}),after(100)))", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 1);

        // Should be a threshold with one real key and the timelock becomes keyless
        match tree {
            DescriptorTree::Threshold(_) => {
                let key_serialized = serialize_descriptor_pubkey(&key);
                let extracted_serialized = serialize_descriptor_pubkey(&keys[0]);
                assert_eq!(extracted_serialized, key_serialized);

                // Test prune_keyless behavior
                let keyless = tree.prune_keyless();
                assert!(keyless.is_some());

                // After removing keyless, should just have a single key
                match keyless.unwrap() {
                    KeylessDescriptorTree::Key(k) => {
                        let k_serialized = serialize_descriptor_pubkey(&k);
                        assert_eq!(k_serialized, key_serialized);
                    }
                    _ => panic!("Expected single key after prune_keyless"),
                }
            }
            _ => panic!("Expected Threshold tree for timelock descriptor"),
        }
    }

    #[test]
    fn test_to_tree_with_hashlocks() {
        // Test a descriptor with hash locks
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        // wsh(or_d(pk(key1),and_v(v:pk(key2),sha256(7924b373d3b1a8269050c572a0b5a5461d8211d5777744c78ca247bc30569b21))))
        let desc_str = format!(
            "wsh(or_d(pk({}),and_v(v:pk({}),sha256(7924b373d3b1a8269050c572a0b5a5461d8211d5777744c78ca247bc30569b21))))",
            key1, key2
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        // Extract keys
        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 2);

        let key_serialized1 = serialize_descriptor_pubkey(&key1);
        let key_serialized2 = serialize_descriptor_pubkey(&key2);

        let extracted_serialized: Vec<_> = keys
            .iter()
            .map(|k| serialize_descriptor_pubkey(k))
            .collect();

        assert!(extracted_serialized.contains(&key_serialized1));
        assert!(extracted_serialized.contains(&key_serialized2));

        // Test prune_keyless
        let keyless = tree.prune_keyless();
        assert!(keyless.is_some());
    }

    #[test]
    fn test_complex_descriptor() {
        // Test a more complex descriptor with multiple conditions
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        // wsh(or_d(pk(key1),and_v(v:thresh(2,pk(key2),pk(key3),older(1000)),after(100))))
        let desc_str = format!(
            "wsh(or_d(pk({}),and_v(v:thresh(2,pk({}),s:pk({}),sln:older(1000)),after(100))))",
            key1, key2, key3
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let tree = desc.to_tree();

        // Extract keys
        let keys = tree.extract_keys();
        assert_eq!(keys.len(), 3);

        let key_serialized1 = serialize_descriptor_pubkey(&key1);
        let key_serialized2 = serialize_descriptor_pubkey(&key2);
        let key_serialized3 = serialize_descriptor_pubkey(&key3);

        let extracted_serialized: Vec<_> = keys
            .iter()
            .map(|k| serialize_descriptor_pubkey(k))
            .collect();

        assert!(extracted_serialized.contains(&key_serialized1));
        assert!(extracted_serialized.contains(&key_serialized2));
        assert!(extracted_serialized.contains(&key_serialized3));
    }

    // Helper function to serialize a descriptor public key for comparison
    fn serialize_descriptor_pubkey(key: &DescriptorPublicKey) -> Vec<u8> {
        match key {
            DescriptorPublicKey::Single(single) => match &single.key {
                miniscript::descriptor::SinglePubKey::FullKey(pk) => pk.inner.serialize().to_vec(),
                miniscript::descriptor::SinglePubKey::XOnly(xpk) => xpk.serialize().to_vec(),
            },
            DescriptorPublicKey::XPub(xpub) => xpub.xkey.encode().to_vec(),
            DescriptorPublicKey::MultiXPub(multi) => multi.xkey.encode().to_vec(),
        }
    }
}
