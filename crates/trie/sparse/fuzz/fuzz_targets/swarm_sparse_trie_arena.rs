#![no_main]

use libfuzzer_sys::fuzz_target;
use reth_trie_sparse_fuzz::{driver::run_arena, input::FuzzInput};

fuzz_target!(|input: FuzzInput| {
    run_arena(input);
});
