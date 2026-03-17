use arbitrary::Arbitrary;

/// Top-level fuzz input. Kept small and seed-driven so libFuzzer can mutate
/// effectively — the actual 500–2000 key initial state is generated at runtime.
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzInput {
    /// Controls parallelism thresholds for both implementations.
    pub profile: ThresholdProfile,
    /// Seed and shape for the initial (large, mostly-blinded) trie state.
    pub initial: InitialStateSpec,
    /// Raw round count — normalized to 20..=100 at runtime.
    pub round_count: u8,
    /// Per-block specifications. Cycled if shorter than `round_count`.
    pub rounds: Vec<BlockSpec>,
}

/// Parallelism threshold presets that target specific code paths.
#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum ThresholdProfile {
    /// All thresholds at 256 — forces serial execution for small blocks.
    Serial256,
    /// All thresholds at 1 — with SinglePrefix hits arena taken.len()==1 fast-path,
    /// with ManyPrefixes triggers real rayon.
    Low1,
    /// Thresholds at 4 — straddles boundary for 3/4/5-item subtrie workloads.
    Boundary4,
    /// Thresholds at 8 — straddles boundary for 7/8/9-item subtrie workloads.
    Boundary8,
}

/// How to generate the large initial key set.
#[derive(Debug, Clone, Arbitrary)]
pub struct InitialStateSpec {
    pub key_seed: u64,
    pub value_seed: u64,
    /// Normalized to 500..=2000.
    pub key_count: u16,
    pub layout: InitialLayout,
}

/// Key distribution for the initial state.
#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum InitialLayout {
    /// Uniform random B256 keys.
    Uniform,
    /// Keys clustered under a few 2-nibble prefixes (subtrie-aware).
    Clustered,
    /// Mix of clustered and uniform.
    Mixed,
}

/// Specification for a single block (round) of updates.
#[derive(Debug, Clone, Arbitrary)]
pub struct BlockSpec {
    /// Which subtrie prefixes to concentrate work under.
    pub subtrie_mode: SubtrieMode,
    /// Raw touch count — normalized to 5..=50.
    pub touch_count: u8,
    /// Raw retain count — normalized to 0..=16.
    pub retain_count: u8,
    /// Percentage of operations that are deletes (0..=40).
    pub delete_pct: u8,
    /// Percentage of operations that are LeafUpdate::Touched (0..=20).
    pub touched_pct: u8,
    /// Pool selection weights (each normalized to 1..=8).
    pub hot_weight: u8,
    pub recent_pruned_weight: u8,
    pub cold_weight: u8,
    pub new_weight: u8,
    /// Seed for key selection and value generation within this block.
    pub key_seed: u64,
    pub value_seed: u64,
    /// Whether to skip pruning this round.
    pub skip_prune: bool,
}

/// Controls how keys are distributed across subtries within a block.
#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum SubtrieMode {
    /// All keys under one 2-nibble prefix — arena sees taken.len()==1.
    SinglePrefix,
    /// Keys split across 2 prefixes — arena can hit real rayon.
    TwoPrefixes,
    /// Keys spread across 4+ prefixes.
    ManyPrefixes,
    /// No prefix constraint.
    Scattered,
}
