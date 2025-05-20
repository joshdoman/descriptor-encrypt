// SPDX-License-Identifier: CC0-1.0

//! # Descriptor Tree
//!
//! TODO...
//!

use miniscript::{
    Legacy, Miniscript, MiniscriptKey, ScriptContext, Segwitv0, Threshold,
    descriptor::{Descriptor, Sh, ShInner, SortedMultiVec, Tr, Wsh, WshInner},
    miniscript::decode::Terminal,
};

type DescriptorNodeThreshold<Pk> = Threshold<DescriptorNode<Pk>, 0>;

/// A node can be keyless, a key, or a threshold of nodes
#[derive(Clone, Debug)]
pub enum DescriptorNode<Pk: MiniscriptKey> {
    /// A keyless node
    Keyless(),
    /// A key
    Key(Pk),
    /// A threshold of nodes
    Threshold(DescriptorNodeThreshold<Pk>),
}

impl<Pk: MiniscriptKey> DescriptorNode<Pk> {
    /// Returns a list of keys in the descriptor
    pub fn extract_keys(&self) -> Vec<Pk> {
        match self {
            DescriptorNode::Keyless() => Vec::new(),
            DescriptorNode::Key(pk) => vec![pk.clone()],
            DescriptorNode::Threshold(thresh) => {
                thresh.iter().flat_map(|node| node.extract_keys()).collect()
            }
        }
    }

    /// Prune keyless nodes assuming they evaluate to `true`.
    /// Sets new_k = max(old_k - num(keyless), 0) in each threshold.
    pub fn prune_keyless(&self) -> Option<DescriptorNode<Pk>> {
        match self {
            DescriptorNode::Keyless() => None,
            DescriptorNode::Key(_) => Some(self.clone()),
            DescriptorNode::Threshold(thresh) => {
                let keyed_nodes: Vec<DescriptorNode<Pk>> = thresh
                    .iter()
                    .filter_map(|node| node.prune_keyless())
                    .collect();

                let new_k = if thresh.k() > thresh.n() - keyed_nodes.len() {
                    thresh.k() - (thresh.n() - keyed_nodes.len())
                } else {
                    0
                };

                match (new_k, keyed_nodes.len()) {
                    (0, _) => None,
                    (1, 1) => Some(keyed_nodes.first().unwrap().clone()),
                    (_, _) => DescriptorNodeThreshold::new(new_k, keyed_nodes)
                        .ok()
                        .map(DescriptorNode::Threshold),
                }
            }
        }
    }

    fn from_ms_and<Ctx>(ms0: &Miniscript<Pk, Ctx>, ms1: &Miniscript<Pk, Ctx>) -> Self
    where
        Ctx: ScriptContext,
    {
        let node0 = ms0.to_node();
        let node1 = ms1.to_node();
        let thresh = DescriptorNodeThreshold::and(node0, node1);

        DescriptorNode::Threshold(thresh)
    }

    fn from_ms_or<Ctx>(ms0: &Miniscript<Pk, Ctx>, ms1: &Miniscript<Pk, Ctx>) -> Self
    where
        Ctx: ScriptContext,
    {
        let node0 = ms0.to_node();
        let node1 = ms1.to_node();
        let thresh = DescriptorNodeThreshold::or(node0, node1);

        DescriptorNode::Threshold(thresh)
    }

    fn from_sortedmulti<Ctx>(sortedmulti: &SortedMultiVec<Pk, Ctx>) -> Self
    where
        Ctx: ScriptContext,
    {
        let nodes = sortedmulti
            .pks()
            .iter()
            .map(|pk| DescriptorNode::Key(pk.clone()))
            .collect();
        let thresh = DescriptorNodeThreshold::new(sortedmulti.k(), nodes).unwrap();

        DescriptorNode::Threshold(thresh)
    }
}

/// A trait to construct a descriptor node
pub trait ToDescriptorNode<Pk: MiniscriptKey> {
    /// Returns a descriptor node
    fn to_node(&self) -> DescriptorNode<Pk>;
}

impl<Pk: MiniscriptKey> ToDescriptorNode<Pk> for Descriptor<Pk> {
    fn to_node(&self) -> DescriptorNode<Pk> {
        match self {
            Descriptor::Sh(sh) => sh.to_node(),
            Descriptor::Wsh(wsh) => wsh.to_node(),
            Descriptor::Tr(tr) => tr.to_node(),
            Descriptor::Wpkh(wpkh) => DescriptorNode::Key(wpkh.clone().into_inner()),
            Descriptor::Pkh(pkh) => DescriptorNode::Key(pkh.clone().into_inner()),
            Descriptor::Bare(bare) => bare.as_inner().to_node(),
        }
    }
}

impl<Pk: MiniscriptKey> ToDescriptorNode<Pk> for Sh<Pk> {
    fn to_node(&self) -> DescriptorNode<Pk> {
        match self.as_inner() {
            ShInner::SortedMulti(sortedmulti) => {
                DescriptorNode::from_sortedmulti::<Legacy>(&sortedmulti)
            }
            ShInner::Wsh(wsh) => wsh.to_node(),
            ShInner::Wpkh(wpkh) => DescriptorNode::Key(wpkh.clone().into_inner()),
            ShInner::Ms(ms) => ms.to_node(),
        }
    }
}

impl<Pk: MiniscriptKey> ToDescriptorNode<Pk> for Wsh<Pk> {
    fn to_node(&self) -> DescriptorNode<Pk> {
        match self.as_inner() {
            WshInner::SortedMulti(sortedmulti) => {
                DescriptorNode::from_sortedmulti::<Segwitv0>(&sortedmulti)
            }
            WshInner::Ms(ms) => ms.to_node(),
        }
    }
}

impl<Pk: MiniscriptKey> ToDescriptorNode<Pk> for Tr<Pk> {
    fn to_node(&self) -> DescriptorNode<Pk> {
        let mut nodes = Vec::new();
        nodes.push(DescriptorNode::Key(self.internal_key().clone()));

        for (_, ms) in self.iter_scripts() {
            nodes.push(ms.to_node());
        }

        let thresh = DescriptorNodeThreshold::or_n(nodes);

        DescriptorNode::Threshold(thresh)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> ToDescriptorNode<Pk> for Miniscript<Pk, Ctx> {
    fn to_node(&self) -> DescriptorNode<Pk> {
        match &self.node {
            Terminal::True => DescriptorNode::Keyless(),
            Terminal::False => DescriptorNode::Keyless(),
            Terminal::PkK(pk) => DescriptorNode::Key(pk.clone()),
            Terminal::PkH(pk) => DescriptorNode::Key(pk.clone()),
            Terminal::RawPkH(_) => DescriptorNode::Keyless(),
            Terminal::After(_) => DescriptorNode::Keyless(),
            Terminal::Older(_) => DescriptorNode::Keyless(),
            Terminal::Sha256(_) => DescriptorNode::Keyless(),
            Terminal::Hash256(_) => DescriptorNode::Keyless(),
            Terminal::Ripemd160(_) => DescriptorNode::Keyless(),
            Terminal::Hash160(_) => DescriptorNode::Keyless(),
            Terminal::Alt(ms) => ms.to_node(),
            Terminal::Swap(ms) => ms.to_node(),
            Terminal::Check(ms) => ms.to_node(),
            Terminal::DupIf(ms) => ms.to_node(),
            Terminal::Verify(ms) => ms.to_node(),
            Terminal::NonZero(ms) => ms.to_node(),
            Terminal::ZeroNotEqual(ms) => ms.to_node(),
            Terminal::AndV(ms0, ms1) => DescriptorNode::from_ms_and(ms0, ms1),
            Terminal::AndB(ms0, ms1) => DescriptorNode::from_ms_and(ms0, ms1),
            Terminal::AndOr(ms0, ms1, ms2) => {
                let and_node = DescriptorNode::from_ms_and(ms0, ms1);
                let or_node = ms2.to_node();
                let thresh = DescriptorNodeThreshold::or(and_node, or_node);

                DescriptorNode::Threshold(thresh)
            }
            Terminal::OrB(ms0, ms1) => DescriptorNode::from_ms_or(ms0, ms1),
            Terminal::OrC(ms0, ms1) => DescriptorNode::from_ms_or(ms0, ms1),
            Terminal::OrD(ms0, ms1) => DescriptorNode::from_ms_or(ms0, ms1),
            Terminal::OrI(ms0, ms1) => DescriptorNode::from_ms_or(ms0, ms1),
            Terminal::Thresh(thresh) => {
                let mut nodes = Vec::new();
                for ms in thresh.iter() {
                    let node = ms.to_node();
                    nodes.push(node);
                }
                let thresh = DescriptorNodeThreshold::new(thresh.k(), nodes).unwrap();

                DescriptorNode::Threshold(thresh)
            }
            Terminal::Multi(thresh) => {
                let nodes = thresh
                    .iter()
                    .map(|pk| DescriptorNode::Key(pk.clone()))
                    .collect();
                let thresh = DescriptorNodeThreshold::new(thresh.k(), nodes).unwrap();

                DescriptorNode::Threshold(thresh)
            }
            Terminal::MultiA(thresh) => {
                let nodes = thresh
                    .iter()
                    .map(|pk| DescriptorNode::Key(pk.clone()))
                    .collect();
                let thresh = DescriptorNodeThreshold::new(thresh.k(), nodes).unwrap();

                DescriptorNode::Threshold(thresh)
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
        let node = DescriptorNode::Key(key.clone());

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&key));
    }

    #[test]
    fn test_extract_keys_threshold() {
        // Create a 2-of-3 threshold
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        let nodes = vec![
            DescriptorNode::Key(key1.clone()),
            DescriptorNode::Key(key2.clone()),
            DescriptorNode::Key(key3.clone()),
        ];

        let thresh = DescriptorNodeThreshold::new(2, nodes).unwrap();
        let node = DescriptorNode::Threshold(thresh);

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&key1));
        assert!(keys.contains(&key2));
        assert!(keys.contains(&key3));
    }

    #[test]
    fn test_extract_keys_with_keyless() {
        // Create a threshold with some keyless nodes
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        let nodes = vec![
            DescriptorNode::Key(key1.clone()),
            DescriptorNode::Keyless::<DescriptorPublicKey>(),
            DescriptorNode::Key(key2.clone()),
        ];

        let thresh = DescriptorNodeThreshold::new(2, nodes).unwrap();
        let node = DescriptorNode::Threshold(thresh);

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&key1));
        assert!(keys.contains(&key2));
    }

    #[test]
    fn test_prune_keyless_single() {
        // Key nodes should remain unchanged
        let key = create_test_key(1);
        let node = DescriptorNode::Key(key.clone());

        let result = node.prune_keyless();
        assert!(result.is_some());

        match result.unwrap() {
            DescriptorNode::Key(k) => assert_eq!(k, key),
            _ => panic!("Expected Key node"),
        }

        // Keyless nodes should return None
        let node = DescriptorNode::Keyless::<DescriptorPublicKey>();
        let result = node.prune_keyless();
        assert!(result.is_none());
    }

    #[test]
    fn test_prune_keyless_threshold() {
        // Create a 2-of-3 threshold with one keyless node
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        let nodes = vec![
            DescriptorNode::Key(key1.clone()),
            DescriptorNode::Keyless::<DescriptorPublicKey>(),
            DescriptorNode::Key(key2.clone()),
        ];

        let thresh = DescriptorNodeThreshold::new(2, nodes).unwrap();
        let node = DescriptorNode::Threshold(thresh);

        let result = node.prune_keyless();
        assert!(result.is_some());

        match result.unwrap() {
            DescriptorNode::Threshold(t) => {
                assert_eq!(t.k(), 1);
                assert_eq!(t.n(), 2);

                // Check that the keyless node was removed
                let keys: Vec<_> = t.iter().flat_map(|n| n.extract_keys()).collect();
                assert_eq!(keys.len(), 2);
                assert!(keys.contains(&key1));
                assert!(keys.contains(&key2));
            }
            _ => panic!("Expected Threshold node"),
        }
    }

    #[test]
    fn test_prune_keyless_reduce_threshold() {
        // Test that k gets reduced to n if needed
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        let nodes = vec![
            DescriptorNode::Key(key1.clone()),
            DescriptorNode::Keyless::<DescriptorPublicKey>(),
            DescriptorNode::Keyless::<DescriptorPublicKey>(),
            DescriptorNode::Key(key2.clone()),
        ];

        let thresh = DescriptorNodeThreshold::new(3, nodes).unwrap();
        let node = DescriptorNode::Threshold(thresh);

        let result = node.prune_keyless();
        assert!(result.is_some());

        match result.unwrap() {
            DescriptorNode::Threshold(t) => {
                assert_eq!(t.k(), 1); // Reduced from 3 to 1
                assert_eq!(t.n(), 2);

                // Check that the keyless nodes were removed
                let keys: Vec<_> = t.iter().flat_map(|n| n.extract_keys()).collect();
                assert_eq!(keys.len(), 2);
            }
            _ => panic!("Expected Threshold node"),
        }
    }

    #[test]
    fn test_prune_keyless_all_nodes_keyless() {
        // Test a scenario where all nodes are keyless
        let nodes = vec![
            DescriptorNode::Keyless::<DescriptorPublicKey>(),
            DescriptorNode::Keyless::<DescriptorPublicKey>(),
        ];

        let thresh = DescriptorNodeThreshold::new(1, nodes).unwrap();
        let node = DescriptorNode::Threshold(thresh);

        let result = node.prune_keyless();
        assert!(result.is_none());
    }

    #[test]
    fn test_prune_keyless_single_key_after_pruning() {
        // Create a threshold with one key and one keyless node
        let key = create_test_key(1);

        let nodes = vec![
            DescriptorNode::Key(key.clone()),
            DescriptorNode::Keyless::<DescriptorPublicKey>(),
        ];

        let thresh = DescriptorNodeThreshold::new(2, nodes).unwrap();
        let node = DescriptorNode::Threshold(thresh);

        let result = node.prune_keyless();
        assert!(result.is_some());

        // After pruning, we should be left with just the key node
        match result.unwrap() {
            DescriptorNode::Key(k) => assert_eq!(k, key),
            _ => panic!("Expected a single Key node"),
        }
    }

    #[test]
    fn test_to_node_wpkh() {
        // Test WPKH descriptor
        let key = create_test_key(1);
        let desc_str = format!("wpkh({})", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        // Should be a single key node
        match node {
            DescriptorNode::Key(k) => match (k, key) {
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
            _ => panic!("Expected Key node for wpkh descriptor"),
        }
    }

    #[test]
    fn test_to_node_pkh() {
        // Test PKH descriptor
        let key = create_test_key(1);
        let desc_str = format!("pkh({})", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        // Should be a single key node
        match node {
            DescriptorNode::Key(_) => {}
            _ => panic!("Expected Key node for pkh descriptor"),
        }
    }

    #[test]
    fn test_to_node_bare_pk() {
        let desc_str = "pk(020000000000000000000000000000000000000000000000000000000000000002)";
        let desc = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();

        let node = desc.to_node();

        // Should be a single key node
        match node {
            DescriptorNode::Key(_) => {}
            _ => panic!("Expected Key node for pkh descriptor"),
        }
    }

    #[test]
    fn test_to_node_wsh_multi() {
        // Test WSH with a multisig
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        let desc_str = format!("wsh(multi(2,{},{},{}))", key1, key2, key3);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 3);

        // Should be a threshold with 3 key nodes
        match node {
            DescriptorNode::Threshold(t) => {
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
            _ => panic!("Expected Threshold node for wsh(multi) descriptor"),
        }
    }

    #[test]
    fn test_to_node_sh_wsh_multi() {
        // Test nested SH-WSH with a multisig
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        let desc_str = format!("sh(wsh(multi(2,{},{})))", key1, key2);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 2);

        // Should be a threshold with 2 key nodes
        match node {
            DescriptorNode::Threshold(t) => {
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
            _ => panic!("Expected Threshold node for sh(wsh(multi)) descriptor"),
        }
    }

    #[test]
    fn test_to_node_tr() {
        // Test taproot descriptor with an internal key and no scripts
        let key = create_test_key(1);
        let desc_str = format!("tr({})", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 1);

        // Should be a threshold node with just the internal key
        match node {
            DescriptorNode::Threshold(t) => {
                assert_eq!(t.n(), 1); // Just the internal key, no scripts

                // Compare serialized keys
                let key_serialized = serialize_descriptor_pubkey(&key);
                let extracted_serialized = serialize_descriptor_pubkey(&keys[0]);
                assert_eq!(extracted_serialized, key_serialized);
            }
            _ => panic!("Expected Threshold node for tr descriptor"),
        }
    }

    #[test]
    fn test_to_node_tr_with_scripts() {
        // Test taproot descriptor with scripts
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        // tr with internal key and one script path spending with key2
        let desc_str = format!("tr({},pk({}))", key1, key2);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 2);

        // Should be a threshold with internal key and script key
        match node {
            DescriptorNode::Threshold(t) => {
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
            _ => panic!("Expected Threshold node for tr descriptor with script"),
        }

        // tr with internal key and two script paths
        let desc_str = format!("tr({},{{pk({}),pk({})}})", key1, key2, key3);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 3);

        // Should be a threshold with internal key and two script keys
        match node {
            DescriptorNode::Threshold(t) => {
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
            _ => panic!("Expected Threshold node for tr descriptor with multiple scripts"),
        }
    }

    #[test]
    fn test_to_node_with_miniscript_and() {
        // Test a descriptor with an AND operation in miniscript
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        // wsh(and_v(v:pk(key1),pk(key2))) - requires both keys
        let desc_str = format!("wsh(and_v(v:pk({}),pk({})))", key1, key2);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 2);

        // Should be a threshold requiring all (k=n)
        match node {
            DescriptorNode::Threshold(t) => {
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
            _ => panic!("Expected Threshold node for AND miniscript"),
        }
    }

    #[test]
    fn test_to_node_with_miniscript_or() {
        // Test a descriptor with an OR operation in miniscript
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        // wsh(or_d(pk(key1),pk(key2))) - requires one of the keys
        let desc_str = format!("wsh(or_d(pk({}),pk({})))", key1, key2);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 2);

        // Should be a 1-of-n threshold
        match node {
            DescriptorNode::Threshold(t) => {
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
            _ => panic!("Expected Threshold node for OR miniscript"),
        }
    }

    #[test]
    fn test_to_node_with_miniscript_thresh() {
        // Test a descriptor with a threshold operation in miniscript
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        // wsh(thresh(2,pk(key1),pk(key2),pk(key3)))
        let desc_str = format!("wsh(thresh(2,pk({}),s:pk({}),s:pk({})))", key1, key2, key3);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 3);

        // Should be a 2-of-3 threshold
        match node {
            DescriptorNode::Threshold(t) => {
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
            _ => panic!("Expected Threshold node for thresh miniscript"),
        }
    }

    #[test]
    fn test_to_node_with_miniscript_andor() {
        // Test a descriptor with an AND_OR operation in miniscript
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);

        // wsh(andor(pk(key1),pk(key2),pk(key3)))
        // Equivalent to: (key1 AND key2) OR key3
        let desc_str = format!("wsh(andor(pk({}),pk({}),pk({})))", key1, key2, key3);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        // Extract keys and ensure all 3 keys are there
        let keys = node.extract_keys();
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
    fn test_to_node_with_timelock() {
        // Test a descriptor with a timelock
        let key = create_test_key(1);

        // wsh(and_v(v:pk(key),after(100)))
        let desc_str = format!("wsh(and_v(v:pk({}),after(100)))", key);
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        let keys = node.extract_keys();
        assert_eq!(keys.len(), 1);

        // Should be a threshold with one real key and the timelock becomes keyless
        match node {
            DescriptorNode::Threshold(_) => {
                let key_serialized = serialize_descriptor_pubkey(&key);
                let extracted_serialized = serialize_descriptor_pubkey(&keys[0]);
                assert_eq!(extracted_serialized, key_serialized);

                // Test prune_keyless behavior
                let keyless = node.prune_keyless();
                assert!(keyless.is_some());

                // After removing keyless, should just have a single key
                match keyless.unwrap() {
                    DescriptorNode::Key(k) => {
                        let k_serialized = serialize_descriptor_pubkey(&k);
                        assert_eq!(k_serialized, key_serialized);
                    }
                    _ => panic!("Expected single key after prune_keyless"),
                }
            }
            _ => panic!("Expected Threshold node for timelock descriptor"),
        }
    }

    #[test]
    fn test_to_node_with_hashlocks() {
        // Test a descriptor with hash locks
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);

        // wsh(or_d(pk(key1),and_v(v:pk(key2),sha256(7924b373d3b1a8269050c572a0b5a5461d8211d5777744c78ca247bc30569b21))))
        let desc_str = format!(
            "wsh(or_d(pk({}),and_v(v:pk({}),sha256(7924b373d3b1a8269050c572a0b5a5461d8211d5777744c78ca247bc30569b21))))",
            key1, key2
        );
        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str).unwrap();

        let node = desc.to_node();

        // Extract keys
        let keys = node.extract_keys();
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
        let keyless = node.prune_keyless();
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

        let node = desc.to_node();

        // Extract keys
        let keys = node.extract_keys();
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

        // Test prune_keyless - should preserve all the key nodes
        let keyless = node.prune_keyless().unwrap();
        let keyless_keys = keyless.extract_keys();
        assert_eq!(keyless_keys.len(), 3);
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
