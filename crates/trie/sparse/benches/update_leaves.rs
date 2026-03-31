#![allow(missing_docs, unreachable_pub)]

use alloy_primitives::{keccak256, map::B256Map, B256};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use reth_trie_sparse::{ArenaParallelSparseTrie, LeafUpdate, SparseTrie};
use std::time::Duration;

const ACCOUNT_BATCH_SIZE: usize = 4_096;
const STORAGE_BATCH_SIZE: usize = 4_096;
const ACCOUNT_VALUE_LEN: usize = 96;
const STORAGE_VALUE_LEN: usize = 32;
const STORAGE_PREFIX: u8 = 0x42;

#[derive(Clone)]
struct UpdateLeavesBenchCase {
    trie: ArenaParallelSparseTrie,
    updates: B256Map<LeafUpdate>,
}

fn update_leaves_large_account_batch(c: &mut Criterion) {
    let case = build_case(*b"acct", ACCOUNT_BATCH_SIZE, ACCOUNT_VALUE_LEN, None);
    c.bench_function("update_leaves_large_account_batch", |b| {
        b.iter_batched(
            || case.clone(),
            |mut case| {
                case.trie
                    .update_leaves(&mut case.updates, |_, _| {
                        panic!("benchmarked account updates should not require proofs")
                    })
                    .expect("account update_leaves should succeed");
                black_box(case.trie);
            },
            BatchSize::LargeInput,
        );
    });
}

fn update_leaves_large_storage_batch(c: &mut Criterion) {
    // Keep every update under a single upper-trie child so the benchmark stresses the large
    // single-subtrie batch shape that makes prefix scanning and per-entry path unpacking hot.
    let case = build_case(*b"stor", STORAGE_BATCH_SIZE, STORAGE_VALUE_LEN, Some(STORAGE_PREFIX));
    c.bench_function("update_leaves_large_storage_batch", |b| {
        b.iter_batched(
            || case.clone(),
            |mut case| {
                case.trie
                    .update_leaves(&mut case.updates, |_, _| {
                        panic!("benchmarked storage updates should not require proofs")
                    })
                    .expect("storage update_leaves should succeed");
                black_box(case.trie);
            },
            BatchSize::LargeInput,
        );
    });
}

fn build_case(
    domain: [u8; 4],
    batch_size: usize,
    value_len: usize,
    fixed_first_byte: Option<u8>,
) -> UpdateLeavesBenchCase {
    let keys: Vec<_> =
        (0..batch_size).map(|idx| make_key(&domain, idx as u64, fixed_first_byte)).collect();

    let mut trie = ArenaParallelSparseTrie::default();
    let mut bootstrap_updates: B256Map<_> = keys
        .iter()
        .enumerate()
        .map(|(idx, key)| {
            (*key, LeafUpdate::Changed(make_value(&domain, idx as u64, value_len, 0)))
        })
        .collect();
    trie.update_leaves(&mut bootstrap_updates, |_, _| {
        panic!("benchmark bootstrap should not require proofs")
    })
    .expect("benchmark bootstrap update_leaves should succeed");
    debug_assert!(bootstrap_updates.is_empty());

    let updates = keys
        .iter()
        .enumerate()
        .map(|(idx, key)| {
            (*key, LeafUpdate::Changed(make_value(&domain, idx as u64, value_len, 1)))
        })
        .collect();

    UpdateLeavesBenchCase { trie, updates }
}

fn make_key(domain: &[u8; 4], idx: u64, fixed_first_byte: Option<u8>) -> B256 {
    let mut seed = [0u8; 16];
    seed[..4].copy_from_slice(domain);
    seed[8..].copy_from_slice(&idx.to_be_bytes());

    let mut key = keccak256(seed);
    if let Some(first_byte) = fixed_first_byte {
        key.0[0] = first_byte;
    }
    key
}

fn make_value(domain: &[u8; 4], idx: u64, len: usize, version: u8) -> Vec<u8> {
    let mut value = Vec::with_capacity(len);
    let mut chunk = 0u8;

    while value.len() < len {
        let mut seed = [0u8; 16];
        seed[..4].copy_from_slice(domain);
        seed[4..12].copy_from_slice(&idx.to_be_bytes());
        seed[12] = version;
        seed[13] = chunk;

        let hash = keccak256(seed);
        let remaining = len - value.len();
        value.extend_from_slice(&hash[..remaining.min(hash.len())]);
        chunk = chunk.wrapping_add(1);
    }

    value
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = update_leaves_large_account_batch, update_leaves_large_storage_batch
}
criterion_main!(benches);
