// SPDX-License-Identifier: CC0-1.0

use itertools::Itertools;
use miniscript::Threshold;
use std::fmt;

/// A tree can a key, or a threshold of trees
#[derive(Clone, Debug)]
pub enum ThresholdTree<T: Clone> {
    /// A leaf
    Leaf(T),
    /// A threshold of trees
    Threshold(Threshold<ThresholdTree<T>, 0>),
}

/// Private enum that extends ThresholdTree with cached path counts
#[derive(Clone, Debug)]
enum ThresholdTreeWithPaths<T: Clone> {
    /// A leaf (exactly 1 path)
    Leaf(T),
    /// A threshold of trees with cached path counts
    Threshold(Threshold<ThresholdTreeWithPaths<T>, 0>, usize, Vec<usize>),
}

/// The maximum number of paths allowed
pub const MAX_PATHS: usize = 20_000;

/// Error type for threshold paths
#[derive(Debug, PartialEq, Eq)]
pub enum ThresholdPathsError {
    /// Error when the total path count exceeds the maximum allowed
    ExcessivePaths,
}

/// Iterator over valid paths through a ThresholdTree
#[derive(Clone, Debug)]
pub struct ThresholdPaths<T: Clone> {
    /// A reference to a threshold tree with cached path counts
    tree: ThresholdTreeWithPaths<T>,
    /// The current path index
    current_index: usize,
}

impl<T: Clone> ThresholdTree<T> {
    /// Get the leaves in the tree
    pub fn leaves(&self) -> Vec<T> {
        match self {
            Self::Leaf(value) => vec![value.clone()],
            Self::Threshold(thresh) => thresh.iter().flat_map(|tree| tree.leaves()).collect(),
        }
    }

    /// Get an iterator over all paths through the tree
    pub fn paths(&self) -> Result<ThresholdPaths<T>, ThresholdPathsError> {
        Ok(ThresholdPaths {
            tree: self.to_tree_with_paths()?,
            current_index: 0,
        })
    }

    /// Convert to a tree with cached path counts
    fn to_tree_with_paths(&self) -> Result<ThresholdTreeWithPaths<T>, ThresholdPathsError> {
        match self {
            ThresholdTree::Leaf(value) => Ok(ThresholdTreeWithPaths::Leaf(value.clone())),
            ThresholdTree::Threshold(t) => {
                if binomial(t.n(), t.k()) > MAX_PATHS {
                    return Err(ThresholdPathsError::ExcessivePaths);
                }

                let nodes: Result<Vec<_>, _> = t.iter().map(|n| n.to_tree_with_paths()).collect();
                let threshold = Threshold::new(t.k(), nodes?).unwrap();

                let subpath_counts: Vec<usize> = threshold
                    .iter()
                    .map(|node| node.num_paths())
                    .combinations(threshold.k())
                    .map(|combo| combo.into_iter().product::<usize>())
                    .collect();

                let path_count = subpath_counts.clone().into_iter().sum();

                if path_count > MAX_PATHS {
                    return Err(ThresholdPathsError::ExcessivePaths);
                }

                Ok(ThresholdTreeWithPaths::Threshold(
                    threshold,
                    path_count,
                    subpath_counts,
                ))
            }
        }
    }
}

impl<T: Clone> ThresholdTreeWithPaths<T> {
    /// Get the leaves in the tree
    pub fn leaves(&self) -> Vec<T> {
        match self {
            Self::Leaf(value) => vec![value.clone()],
            Self::Threshold(thresh, ..) => thresh.iter().flat_map(|tree| tree.leaves()).collect(),
        }
    }

    /// Get the cached path count
    fn num_paths(&self) -> usize {
        match self {
            ThresholdTreeWithPaths::Leaf(_) => 1,
            ThresholdTreeWithPaths::Threshold(_, count, _) => *count,
        }
    }

    /// Get a specific path by index
    pub fn get_path(&self, i: usize) -> Option<Vec<T>> {
        if i >= self.num_paths() {
            return None;
        }
        let mut path = Vec::new();
        self.extend_path(i, &mut path);
        Some(path)
    }

    fn extend_path(&self, mut i: usize, path: &mut Vec<T>) {
        match self {
            ThresholdTreeWithPaths::Leaf(value) => path.push(value.clone()),
            ThresholdTreeWithPaths::Threshold(t, _, subpath_counts) => {
                let mut combo_index = 0;
                for &subpath_count in subpath_counts {
                    if i < subpath_count {
                        break;
                    }
                    i -= subpath_count;
                    combo_index += 1;
                }

                let combo = combination_indices(t.n(), t.k(), combo_index);

                for &idx in &combo {
                    let node = &t.data()[idx];

                    node.extend_path(i % node.num_paths(), path);
                    i /= node.num_paths();
                }
            }
        }
    }
}

impl<T: Clone> ThresholdPaths<T> {
    /// Get the leaves in the tree
    pub fn leaves(&self) -> Vec<T> {
        self.tree.leaves()
    }

    /// Get the number of paths
    pub fn num_paths(&self) -> usize {
        self.tree.num_paths()
    }

    /// Get a specific path by index
    pub fn get_path(&self, i: usize) -> Option<Vec<T>> {
        self.tree.get_path(i)
    }
}

impl<T: Clone> Iterator for ThresholdPaths<T> {
    type Item = Vec<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.num_paths() {
            return None;
        }

        let result = self.get_path(self.current_index);
        self.current_index += 1;
        result
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.num_paths() - self.current_index;
        (remaining, Some(remaining))
    }
}

impl std::error::Error for ThresholdPathsError {}

impl fmt::Display for ThresholdPathsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThresholdPathsError::ExcessivePaths => {
                write!(f, "Path count exceeds the maximum allowed ({})", MAX_PATHS)
            }
        }
    }
}

/// Helper function to calculate the combination at a specific index
fn combination_indices(n: usize, k: usize, mut i: usize) -> Vec<usize> {
    let mut result = Vec::with_capacity(k);
    let mut next = 0;

    for j in 1..=k {
        while next < n - k + j {
            let combinations = binomial(n - 1 - next, k - j);
            if i < combinations {
                break;
            }
            i -= combinations;
            next += 1;
        }
        result.push(next);
        next += 1;
    }

    result
}

fn binomial(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    if k == 0 || k == n {
        return 1;
    }

    let k = k.min(n - k);
    let mut c: usize = 1;

    for i in 0..k {
        c = c.saturating_mul(n - i) / (i + 1);
    }

    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // Helper to create leaf nodes quickly
    fn leaf<T: Clone>(value: T) -> ThresholdTree<T> {
        ThresholdTree::Leaf(value)
    }

    // Helper to create threshold nodes quickly
    fn threshold<T: Clone>(k: usize, nodes: Vec<ThresholdTree<T>>) -> ThresholdTree<T> {
        ThresholdTree::Threshold(Threshold::from_iter(k, nodes.into_iter()).unwrap())
    }

    #[test]
    fn test_single_leaf() {
        // Single leaf should have exactly one path
        let tree = leaf(42);
        let paths: Vec<_> = tree.paths().unwrap().collect();

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec![42]);
    }

    #[test]
    fn test_1_of_2_threshold() {
        // 1-of-2 threshold should have 2 paths
        let tree = threshold(1, vec![leaf("a"), leaf("b")]);
        let paths: Vec<_> = tree.paths().unwrap().collect();

        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec!["a"]));
        assert!(paths.contains(&vec!["b"]));
    }

    #[test]
    fn test_2_of_2_threshold() {
        // 2-of-2 threshold should have 1 path containing both leaves
        let tree = threshold(2, vec![leaf("a"), leaf("b")]);
        let paths: Vec<_> = tree.paths().unwrap().collect();

        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec!["a", "b"]);
    }

    #[test]
    fn test_2_of_3_threshold() {
        // 2-of-3 threshold should have 3 paths
        let tree = threshold(2, vec![leaf("a"), leaf("b"), leaf("c")]);
        let paths: Vec<_> = tree.paths().unwrap().collect();

        assert_eq!(paths.len(), 3);
        let path_set: HashSet<Vec<&str>> = paths.into_iter().collect();
        assert!(path_set.contains(&vec!["a", "b"]));
        assert!(path_set.contains(&vec!["a", "c"]));
        assert!(path_set.contains(&vec!["b", "c"]));
    }

    #[test]
    fn test_nested_threshold() {
        // Tests a more complex nested structure:
        // 2-of-3(leaf("a"), leaf("b"), 1-of-2(leaf("c"), leaf("d")))
        let inner = threshold(1, vec![leaf("c"), leaf("d")]);
        let tree = threshold(2, vec![leaf("a"), leaf("b"), inner]);
        let paths: Vec<_> = tree.paths().unwrap().collect();

        assert_eq!(paths.len(), 5);
        let path_set: HashSet<Vec<&str>> = paths.into_iter().collect();
        assert!(path_set.contains(&vec!["a", "b"]));
        assert!(path_set.contains(&vec!["a", "c"]));
        assert!(path_set.contains(&vec!["a", "d"]));
        assert!(path_set.contains(&vec!["b", "c"]));
        assert!(path_set.contains(&vec!["b", "d"]));
    }

    #[test]
    fn test_deeply_nested() {
        // A more complex tree with multiple levels of nesting
        let inner1 = threshold(1, vec![leaf(1), leaf(2)]); // num = 2
        let inner2 = threshold(2, vec![leaf(3), leaf(4), leaf(5)]); // num = 3
        let inner3 = threshold(1, vec![inner1.clone(), inner2.clone()]); // num = 2 + 3 = 5
        let tree = threshold(2, vec![leaf(0), inner1, inner2, inner3]);

        // num = 1 * (2 + 3 + 5) + 2 * (3 + 5) + 3 * 5 = 41
        let paths = tree.paths().unwrap();
        assert_eq!(paths.num_paths(), 41);

        // Check path retrieval
        let path23 = tree.paths().unwrap().get_path(23).unwrap();
        assert_eq!(path23, vec![2, 3, 5]);
    }

    #[test]
    fn test_iterator_properties() {
        // Test iterator behavior
        let tree = threshold(2, vec![leaf("a"), leaf("b"), leaf("c")]);
        let mut iter = tree.paths().unwrap();

        // Size hint should match actual count
        assert_eq!(iter.size_hint(), (3, Some(3)));

        // After consuming one item
        iter.next();
        assert_eq!(iter.size_hint(), (2, Some(2)));

        // After consuming all items
        iter.next();
        iter.next();
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_large_threshold() {
        // Test with larger tree to ensure efficiency
        let leaves = (0..16).map(leaf).collect::<Vec<_>>();
        let tree = threshold(8, leaves);

        // Should have C(16,8) = 12870 paths
        assert_eq!(tree.paths().unwrap().num_paths(), 12870);

        // Test if we can get all paths without performance issues
        assert_eq!(tree.paths().unwrap().count(), 12870);
    }

    #[test]
    fn test_excessive_paths() {
        // Create a tree that would far exceed MAX_PATHS
        let leaves = (0..100).map(leaf).collect::<Vec<_>>();
        let huge_tree = threshold(50, leaves);

        assert_eq!(
            huge_tree.paths().unwrap_err(),
            ThresholdPathsError::ExcessivePaths
        );

        // Create a tree that would barely exceed MAX_PATHS
        let leaves = (0..17).map(leaf).collect::<Vec<_>>();
        let big_tree = threshold(8, leaves);

        assert_eq!(
            big_tree.paths().unwrap_err(),
            ThresholdPathsError::ExcessivePaths
        );

        // Ensure trees just under the limit work properly
        let small_leaves = (0..16).map(leaf).collect::<Vec<_>>();
        let small_tree = threshold(8, small_leaves);
        assert!(small_tree.paths().is_ok());

        // Test a threshold that is a 1-of-2 of identical 8-of-16 thresholds
        let inner_leaves = (0..16).map(leaf).collect::<Vec<_>>();
        let inner_threshold1 = threshold(8, inner_leaves.clone());
        let inner_threshold2 = threshold(8, inner_leaves);
        let combined_tree = threshold(1, vec![inner_threshold1, inner_threshold2]);

        // This should fail because 1-of-2 of 8-of-16 thresholds would create
        // 12,870 + 12,870 = 25,740 paths, which exceeds MAX_PATHS (20,000)
        assert_eq!(
            combined_tree.paths().unwrap_err(),
            ThresholdPathsError::ExcessivePaths
        );
    }
}
