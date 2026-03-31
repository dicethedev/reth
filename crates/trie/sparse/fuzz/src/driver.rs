use alloy_primitives::{B256, map::B256Map};
use rand::{SeedableRng, rngs::StdRng};
use reth_trie::{EMPTY_ROOT_HASH, test_utils::TrieTestHarness};
use reth_trie_common::{Nibbles, ProofV2Target};
use reth_trie_sparse::{
    ArenaParallelSparseTrie, ArenaParallelismThresholds, LeafUpdate, ParallelSparseTrie,
    ParallelismThresholds, SparseTrie,
};

use crate::input::{BlockSpec, FuzzInput, RoundOp, ThresholdProfile};
use crate::model::{
    apply_changeset_to_live_state, build_initial_storage, choose_retained_keys, collect_proof_requests,
    realize_block,
};
use crate::pools::KeyPools;

/// Maximum number of reveal-update retry iterations before we give up.
const MAX_RETRY_ITERS: usize = 64;
/// Per-round operation count bounds.
const MIN_ROUND_OPS: usize = 3;
const MAX_ROUND_OPS: usize = 10;

#[derive(Debug, Clone, Copy)]
enum TrieResetKind {
    Clear,
    Wipe,
}

/// Fuzzer entry point for the arena-backed sparse trie.
pub fn run_arena(input: FuzzInput) {
    run_with_trie(input, |profile| {
        ArenaParallelSparseTrie::default()
            .with_parallelism_thresholds(materialize_arena_thresholds(profile))
    }, "arena");
}

/// Fuzzer entry point for the map-backed sparse trie.
pub fn run_map(input: FuzzInput) {
    run_with_trie(input, |profile| {
        ParallelSparseTrie::default().with_parallelism_thresholds(materialize_map_thresholds(profile))
    }, "map");
}

fn run_with_trie<T, F>(input: FuzzInput, make_trie: F, trie_label: &str)
where
    T: SparseTrie,
    F: FnOnce(ThresholdProfile) -> T,
{
    let round_count = 20 + (input.round_count as usize % 81);

    // Early exit if no rounds specified (libfuzzer can generate empty vecs).
    if input.rounds.is_empty() {
        return;
    }

    // 1. Build initial state.
    let initial_storage = build_initial_storage(&input.initial);

    let mut live_state = initial_storage.clone();
    let mut harness = TrieTestHarness::new(initial_storage);

    // 2. Root-only reveal — maximally blinded start.
    let root_node = harness.root_node();
    let mut trie = make_trie(input.profile);

    trie.set_root(root_node.node, root_node.masks, true)
        .unwrap_or_else(|err| panic!("{trie_label} set_root should succeed: {err}"));

    let mut pools = KeyPools::from_storage(&live_state);

    for round_idx in 0..round_count {
        // Cycle through the block specs if fewer than round_count.
        let spec = &input.rounds[round_idx % input.rounds.len()];

        // Build one production-like small block.
        let crate::model::RealizedBlock { leaf_updates, changeset, touched_keys } =
            realize_block(spec, &live_state, &mut pools);
        let mut pending = leaf_updates;
        let mut pending_changeset = Some(changeset);

        let mut updates_applied = false;
        // Pruning requires cached hashes, so we only allow it after roots have been
        // checkpointed since the most recent successful ApplyUpdates.
        let mut roots_fresh_since_last_apply = true;
        let mut pruned_this_round = false;

        let ops = materialize_round_ops(spec);
        for (op_idx, op) in ops.into_iter().enumerate() {
            match op {
                RoundOp::ApplyUpdates => {
                    apply_pending_updates(
                        &mut trie,
                        &mut harness,
                        &mut pending,
                        round_idx,
                        op_idx,
                        trie_label,
                    );

                    if !updates_applied {
                        let changeset = pending_changeset
                            .take()
                            .expect("changeset should be available before first apply");
                        apply_changeset_to_live_state(&mut live_state, &changeset);
                        harness.apply_changeset(changeset);
                        updates_applied = true;
                        roots_fresh_since_last_apply = false;
                    }
                }
                RoundOp::Prune => {
                    if !roots_fresh_since_last_apply {
                        checkpoint_root(&mut trie, &harness, round_idx, Some(op_idx), trie_label);
                        roots_fresh_since_last_apply = true;
                    }

                    let mut prune_rng = StdRng::seed_from_u64(
                        spec.key_seed
                            .wrapping_add((round_idx as u64) << 16)
                            .wrapping_add(op_idx as u64),
                    );
                    let retained = choose_retained_keys(
                        spec,
                        &touched_keys,
                        &live_state,
                        &mut prune_rng,
                    );

                    let mut retained_paths: Vec<Nibbles> =
                        retained.iter().map(|k| Nibbles::unpack(*k)).collect();
                    retained_paths.sort_unstable();
                    retained_paths.dedup();

                    trie.prune(&retained_paths);

                    pools.observe_prune(&touched_keys, &retained, &live_state);
                    pruned_this_round = true;
                }
                RoundOp::CheckpointRoot => {
                    checkpoint_root(&mut trie, &harness, round_idx, Some(op_idx), trie_label);
                    roots_fresh_since_last_apply = true;
                }
                RoundOp::ClearAndReload => {
                    reset_trie_to_current_state(
                        &mut trie,
                        &harness,
                        round_idx,
                        op_idx,
                        trie_label,
                        TrieResetKind::Clear,
                    );
                    pools.observe_reset();
                    pruned_this_round = true;
                    roots_fresh_since_last_apply = true;
                }
                RoundOp::WipeAndReload => {
                    reset_trie_to_current_state(
                        &mut trie,
                        &harness,
                        round_idx,
                        op_idx,
                        trie_label,
                        TrieResetKind::Wipe,
                    );
                    pools.observe_reset();
                    pruned_this_round = true;
                    roots_fresh_since_last_apply = true;
                }
            }
        }

        // Ensure rounds eventually apply updates even if the op schedule omitted ApplyUpdates.
        if !updates_applied {
            apply_pending_updates(
                &mut trie,
                &mut harness,
                &mut pending,
                round_idx,
                usize::MAX,
                trie_label,
            );

            let changeset =
                pending_changeset.take().expect("changeset should exist when applying at round end");
            apply_changeset_to_live_state(&mut live_state, &changeset);
            harness.apply_changeset(changeset);
            updates_applied = true;
        }

        // Always checkpoint at end of round to keep strong invariants regardless of op schedule.
        if updates_applied {
            let expected_root = checkpoint_root(&mut trie, &harness, round_idx, None, trie_label);
            commit_tracked_updates(&mut trie, expected_root, round_idx, trie_label);
        }

        if !pruned_this_round {
            pools.observe_no_prune(&touched_keys, &live_state);
        }
    }
}

fn materialize_round_ops(spec: &BlockSpec) -> Vec<RoundOp> {
    if spec.ops.is_empty() {
        return vec![
            RoundOp::ApplyUpdates,
            RoundOp::CheckpointRoot,
            RoundOp::Prune,
            RoundOp::CheckpointRoot,
            RoundOp::ClearAndReload,
            RoundOp::WipeAndReload,
        ];
    }

    let op_count = MIN_ROUND_OPS + (spec.op_count as usize % (MAX_ROUND_OPS - MIN_ROUND_OPS + 1));
    spec.ops.iter().copied().cycle().take(op_count).collect()
}

fn apply_pending_updates<T: SparseTrie>(
    trie: &mut T,
    harness: &mut TrieTestHarness,
    pending: &mut B256Map<LeafUpdate>,
    round_idx: usize,
    op_idx: usize,
    trie_label: &str,
) {
    for _ in 0..MAX_RETRY_ITERS {
        let requests = collect_proof_requests(trie, pending);
        let mut targets: Vec<ProofV2Target> = requests
            .into_iter()
            .map(|(key, min_len)| ProofV2Target::new(key).with_min_len(min_len))
            .collect();
        if targets.is_empty() {
            break;
        }

        let (mut proof_nodes, _) = harness.proof_v2(&mut targets);

        trie.reveal_nodes(&mut proof_nodes)
            .unwrap_or_else(|err| panic!("{trie_label} reveal_nodes should succeed: {err}"));
    }

    assert!(
        pending.is_empty(),
        "{trie_label} has pending updates after retry budget (round {round_idx}, op {op_idx})"
    );
}

fn checkpoint_root<T: SparseTrie>(
    trie: &mut T,
    harness: &TrieTestHarness,
    round_idx: usize,
    op_idx: Option<usize>,
    trie_label: &str,
) -> B256 {
    let trie_root = trie.root();
    let expected_root = harness.original_root();

    let phase = op_idx.map_or_else(|| "end".to_string(), |idx| format!("op {idx}"));
    assert_eq!(
        trie_root, expected_root,
        "oracle mismatch at round {round_idx} ({phase}): {trie_label}={trie_root} expected={expected_root}"
    );

    trie_root
}

fn commit_tracked_updates<T: SparseTrie>(
    trie: &mut T,
    expected_root: B256,
    round_idx: usize,
    trie_label: &str,
) {
    let updates = trie.take_updates();
    trie.commit_updates(&updates.updated_nodes, &updates.removed_nodes);

    let committed_root = trie.root();
    assert_eq!(
        committed_root, expected_root,
        "root changed after commit_updates at round {round_idx}: {trie_label}={committed_root} expected={expected_root}"
    );
}

fn reset_trie_to_current_state<T: SparseTrie>(
    trie: &mut T,
    harness: &TrieTestHarness,
    round_idx: usize,
    op_idx: usize,
    trie_label: &str,
    reset_kind: TrieResetKind,
) {
    let reset_name = match reset_kind {
        TrieResetKind::Clear => {
            trie.clear();
            "clear"
        }
        TrieResetKind::Wipe => {
            trie.wipe();
            "wipe"
        }
    };

    let empty_root = trie.root();
    assert_eq!(
        empty_root, EMPTY_ROOT_HASH,
        "{trie_label} {reset_name} should produce EMPTY_ROOT_HASH at round {round_idx}, op {op_idx}"
    );

    let updates = trie.take_updates();
    assert_eq!(
        updates.wiped,
        matches!(reset_kind, TrieResetKind::Wipe),
        "{trie_label} {reset_name} update tracking mismatch at round {round_idx}, op {op_idx}"
    );

    let root_node = harness.root_node();
    trie.set_root(root_node.node, root_node.masks, true).unwrap_or_else(|err| {
        panic!(
            "{trie_label} set_root should succeed after {reset_name} at round {round_idx}, op {op_idx}: {err}"
        )
    });

    let reloaded_root = trie.root();
    let expected_root = harness.original_root();
    assert_eq!(
        reloaded_root, expected_root,
        "{trie_label} root mismatch after {reset_name}+reload at round {round_idx}, op {op_idx}: {reloaded_root} expected={expected_root}"
    );
}

const fn threshold_value(profile: ThresholdProfile) -> usize {
    match profile {
        ThresholdProfile::Serial256 => 256,
        ThresholdProfile::Low1 => 1,
        ThresholdProfile::Boundary4 => 4,
        ThresholdProfile::Boundary8 => 8,
    }
}

fn materialize_arena_thresholds(profile: ThresholdProfile) -> ArenaParallelismThresholds {
    let val = threshold_value(profile);

    ArenaParallelismThresholds {
        min_dirty_leaves: val as u64,
        min_revealed_nodes: val,
        min_updates: val,
        min_leaves_for_prune: val as u64,
    }
}

fn materialize_map_thresholds(profile: ThresholdProfile) -> ParallelismThresholds {
    let val = threshold_value(profile);

    ParallelismThresholds {
        min_revealed_nodes: val,
        min_updated_nodes: val,
    }
}
