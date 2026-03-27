use super::*;
use reth_trie_common::{BranchNodeV2, LeafNode, ProofTrieNodeV2, RlpNode, TrieMask};
use reth_trie_sparse::ParallelSparseTrie;

fn create_branch_node_with_children(
    children_indices: &[u8],
    child_hashes: impl IntoIterator<Item = RlpNode>,
) -> TrieNodeV2 {
    let mut stack = Vec::new();
    let mut state_mask = TrieMask::default();

    for (&idx, hash) in children_indices.iter().zip(child_hashes) {
        state_mask.set_bit(idx);
        stack.push(hash);
    }

    TrieNodeV2::Branch(BranchNodeV2::new(Nibbles::default(), stack, state_mask, None))
}

fn create_leaf_node(key: impl AsRef<[u8]>, value_byte: u8) -> TrieNodeV2 {
    TrieNodeV2::Leaf(LeafNode::new(Nibbles::from_nibbles(key), vec![value_byte]))
}

#[cfg(debug_assertions)]
#[test]
fn test_parallel_reveal_nodes_panics_for_divergent_same_depth_lower_paths() {
    // Make lower subtrie [0x1, 0x2] reachable from the upper trie.
    let root_branch =
        create_branch_node_with_children(&[0x1], [RlpNode::word_rlp(&B256::repeat_byte(0xAA))]);
    let branch_at_1 =
        create_branch_node_with_children(&[0x2], [RlpNode::word_rlp(&B256::repeat_byte(0xBB))]);

    let mut trie = ParallelSparseTrie::default();
    trie.set_root(root_branch, None, false).unwrap();
    trie.reveal_nodes(&mut [ProofTrieNodeV2 {
        path: Nibbles::from_nibbles([0x1]),
        node: branch_at_1,
        masks: None,
    }])
    .unwrap();

    // Both nodes belong to the same lower subtrie index (prefix [0x1, 0x2]) but diverge at the
    // next nibble. Revealing the first node sets the subtrie root path too deep; revealing the
    // second then trips `debug_assert!(path.starts_with(&self.path))`.
    trie.reveal_nodes(&mut [
        ProofTrieNodeV2 {
            path: Nibbles::from_nibbles([0x1, 0x2, 0x3]),
            node: create_leaf_node([0x0], 1),
            masks: None,
        },
        ProofTrieNodeV2 {
            path: Nibbles::from_nibbles([0x1, 0x2, 0x4]),
            node: create_leaf_node([0x0], 2),
            masks: None,
        },
    ])
    .unwrap();
}

#[test]
fn test_parallel_root_panics_when_lower_subtrie_path_has_no_node() {
    // `wipe` marks all keys as changed (prefix_set = all). `set_root` does not clear this.
    let mut trie = ParallelSparseTrie::default();
    trie.wipe();

    // Make lower subtrie [0x0, 0xa] reachable from the upper trie.
    let root_branch =
        create_branch_node_with_children(&[0x0], [RlpNode::word_rlp(&B256::repeat_byte(0xAA))]);
    let branch_at_0 =
        create_branch_node_with_children(&[0xa], [RlpNode::word_rlp(&B256::repeat_byte(0xBB))]);
    trie.set_root(root_branch, None, false).unwrap();
    trie.reveal_nodes(&mut [ProofTrieNodeV2 {
        path: Nibbles::from_nibbles([0x0]),
        node: branch_at_0,
        masks: None,
    }])
    .unwrap();

    // This sets lower subtrie path to 0x0a3 but does not insert a node at 0x0a3 because parent
    // branch 0x0a is not revealed.
    trie.reveal_nodes(&mut [ProofTrieNodeV2 {
        path: Nibbles::from_nibbles([0x0, 0xa, 0x3]),
        node: create_leaf_node([0x0], 1),
        masks: None,
    }])
    .unwrap();

    // `root()` now forces lower subtrie hash recomputation and panics when starting from the
    // stale subtrie.path with no backing node.
    let _ = trie.root();
}
