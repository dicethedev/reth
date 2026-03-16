---
reth-engine-tree: minor
reth-node-builder: minor
---

Added `EngineSharedCaches` struct that bundles `PayloadExecutionCache`, `SharedPreservedSparseTrie`, and `PrecompileCacheMap` into a single launcher-owned handle. Updated `PayloadProcessor::new()` and `EngineValidatorBuilder::build_tree_validator` to accept `EngineSharedCaches`.
