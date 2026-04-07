use dashmap::DashMap;
use ffi::MDBX_cache_entry_t;
use smallvec::SmallVec;

/// Key type for the B-tree traversal cache: `(dbi, key_bytes)`.
///
/// Uses `SmallVec` to avoid heap allocation for keys up to 64 bytes.
type CacheKey = (ffi::MDBX_dbi, SmallVec<[u8; 64]>);

/// Per-environment store of [`MDBX_cache_entry_t`] entries, keyed by `(dbi, key)`.
///
/// Each entry stores B-tree page offsets and version metadata that lets
/// [`ffi::mdbx_cache_get`] skip the root-to-leaf tree walk when the target
/// page hasn't been modified since the last lookup.
#[derive(Debug)]
pub struct CacheStore {
    inner: DashMap<CacheKey, MDBX_cache_entry_t>,
}

impl CacheStore {
    /// Creates a new, empty cache store.
    pub fn new() -> Self {
        Self { inner: DashMap::new() }
    }

    /// Returns a reference to the inner map.
    #[inline]
    pub(crate) const fn map(&self) -> &DashMap<CacheKey, MDBX_cache_entry_t> {
        &self.inner
    }
}

impl Default for CacheStore {
    fn default() -> Self {
        Self::new()
    }
}
