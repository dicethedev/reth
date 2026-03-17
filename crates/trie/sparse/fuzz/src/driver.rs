use rand::{SeedableRng, rngs::StdRng};
use reth_trie::test_utils::TrieTestHarness;
use reth_trie_common::Nibbles;
use reth_trie_sparse::{
    ArenaParallelSparseTrie, ArenaParallelismThresholds, ParallelSparseTrie,
    ParallelismThresholds, SparseTrie,
};

use crate::input::{FuzzInput, ThresholdProfile};
use crate::model::{
    apply_changeset_to_live_state, build_initial_storage, choose_retained_keys,
    collect_proof_requests, merge_requests, realize_block,
};
use crate::pools::KeyPools;

/// Maximum number of reveal-update retry iterations before we give up.
const MAX_RETRY_ITERS: usize = 64;

/// Main fuzzer entry point. Drives both SparseTrie implementations through
/// the same multi-block lifecycle and asserts they agree on roots.
pub fn run(input: FuzzInput) {
    let round_count = 20 + (input.round_count as usize % 81);

    // Early exit if no rounds specified (libfuzzer can generate empty vecs).
    if input.rounds.is_empty() {
        return;
    }

    // 1. Build large initial state.
    let initial_storage = build_initial_storage(&input.initial);
    if initial_storage.is_empty() {
        return;
    }

    let mut live_state = initial_storage.clone();
    let mut harness = TrieTestHarness::new(initial_storage);

    // 2. Root-only reveal — maximally blinded start.
    let root_node = harness.root_node();

    let (arena_thresholds, map_thresholds) = materialize_thresholds(input.profile);

    let mut arena = ArenaParallelSparseTrie::default()
        .with_parallelism_thresholds(arena_thresholds);
    let mut map_trie = ParallelSparseTrie::default()
        .with_parallelism_thresholds(map_thresholds);

    arena
        .set_root(root_node.node.clone(), root_node.masks, false)
        .expect("arena set_root should succeed");
    map_trie
        .set_root(root_node.node, root_node.masks, false)
        .expect("map set_root should succeed");

    let mut pools = KeyPools::from_storage(&live_state);

    for round_idx in 0..round_count {
        // Cycle through the block specs if fewer than round_count.
        let spec = &input.rounds[round_idx % input.rounds.len()];

        // 3. Build one production-like small block.
        let block = realize_block(spec, &live_state, &mut pools);

        let mut pending_arena = block.leaf_updates.clone();
        let mut pending_map = block.leaf_updates;

        // 4. Joint reveal-update loop against ONE proof source.
        for _ in 0..MAX_RETRY_ITERS {
            let arena_requests = collect_proof_requests(&mut arena, &mut pending_arena);
            let map_requests = collect_proof_requests(&mut map_trie, &mut pending_map);

            let mut targets = merge_requests(arena_requests, map_requests);

            if targets.is_empty() {
                break;
            }

            let (mut proof_nodes, _) = harness.proof_v2(&mut targets);

            // reveal_nodes mutates the slice, so clone for the second implementation.
            let mut proof_nodes_for_map = proof_nodes.clone();

            arena.reveal_nodes(&mut proof_nodes).expect("arena reveal_nodes should succeed");
            map_trie
                .reveal_nodes(&mut proof_nodes_for_map)
                .expect("map reveal_nodes should succeed");
        }

        assert!(pending_arena.is_empty(), "arena has pending updates after retry budget (round {round_idx})");
        assert!(pending_map.is_empty(), "map has pending updates after retry budget (round {round_idx})");

        // 5. Roots must match after block execution.
        let arena_root = arena.root();
        let map_root = map_trie.root();
        assert_eq!(
            arena_root, map_root,
            "impl divergence at round {round_idx}: arena={arena_root} map={map_root}"
        );

        // 6. Advance oracle model.
        apply_changeset_to_live_state(&mut live_state, &block.changeset);
        harness.apply_changeset(block.changeset);
        let expected_root = harness.original_root();

        assert_eq!(
            arena_root, expected_root,
            "oracle mismatch at round {round_idx}: arena={arena_root} expected={expected_root}"
        );

        // 7. Prune (unless this round skips it).
        if !spec.skip_prune {
            let mut prune_rng = StdRng::seed_from_u64(spec.key_seed.wrapping_add(round_idx as u64));
            let retained = choose_retained_keys(spec, &block.touched_keys, &live_state, &mut prune_rng);

            let mut retained_paths: Vec<Nibbles> =
                retained.iter().map(|k| Nibbles::unpack(*k)).collect();
            retained_paths.sort_unstable();
            retained_paths.dedup();

            arena.prune(&retained_paths);
            map_trie.prune(&retained_paths);

            // Root must be unchanged after prune.
            let arena_root_post = arena.root();
            let map_root_post = map_trie.root();
            assert_eq!(
                arena_root_post, expected_root,
                "arena root changed after prune at round {round_idx}"
            );
            assert_eq!(
                map_root_post, expected_root,
                "map root changed after prune at round {round_idx}"
            );

            pools.observe_prune(&block.touched_keys, &retained, &live_state);
        } else {
            pools.observe_no_prune(&block.touched_keys, &live_state);
        }
    }
}

/// Convert a threshold profile into concrete thresholds for both implementations.
fn materialize_thresholds(
    profile: ThresholdProfile,
) -> (ArenaParallelismThresholds, ParallelismThresholds) {
    let val = match profile {
        ThresholdProfile::Serial256 => 256,
        ThresholdProfile::Low1 => 1,
        ThresholdProfile::Boundary4 => 4,
        ThresholdProfile::Boundary8 => 8,
    };

    let arena = ArenaParallelismThresholds {
        min_dirty_leaves: val as u64,
        min_revealed_nodes: val,
        min_updates: val,
        min_leaves_for_prune: val as u64,
    };

    let map = ParallelismThresholds {
        min_revealed_nodes: val,
        min_updated_nodes: val,
    };

    (arena, map)
}
