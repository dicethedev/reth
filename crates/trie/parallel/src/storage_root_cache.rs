use core::fmt;

use alloy_primitives::{map::DefaultHashBuilder, B256};
use moka::policy::EvictionPolicy;

/// Default max entry count for the shared storage-root cache.
const DEFAULT_STORAGE_ROOT_CACHE_MAX_ENTRIES: u64 = 100_000;

/// Concurrent LRU cache of storage roots shared across proof workers and continuation blocks.
///
/// The storage roots are pre-state.
#[derive(Clone)]
pub struct StorageRootCache(moka::sync::Cache<B256, B256, DefaultHashBuilder>);

impl StorageRootCache {
    /// Creates a new cache with the given maximum number of entries.
    pub fn new(max_entries: u64) -> Self {
        let max_entries = max_entries.max(1);
        Self(
            moka::sync::CacheBuilder::new(max_entries)
                .eviction_policy(EvictionPolicy::lru())
                .build_with_hasher(Default::default()),
        )
    }

    /// Returns the cached root for the given hashed address, if cached.
    #[inline]
    pub fn get(&self, hashed_address: &B256) -> Option<B256> {
        self.0.get(hashed_address)
    }

    /// Inserts or overwrites the cached root for the given hashed address.
    #[inline]
    pub fn insert(&self, hashed_address: B256, root: B256) {
        self.0.insert(hashed_address, root);
    }

    /// Invalidates all cached roots.
    #[inline]
    pub fn clear(&self) {
        // `invalidate_all` performs lazy invalidation. At the same time we are not running any
        // background maintenance tasks which means maintenance is shifted to the access ops. This
        // also makes `entry_count` inaccurate and we are not using it for now.
        self.0.invalidate_all();
    }
}

impl Default for StorageRootCache {
    fn default() -> Self {
        Self::new(DEFAULT_STORAGE_ROOT_CACHE_MAX_ENTRIES)
    }
}

impl fmt::Debug for StorageRootCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageRootCache").field("entry_count", &self.0.entry_count()).finish()
    }
}
