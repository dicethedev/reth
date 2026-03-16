//! Command for replaying a reorg between two existing block hashes.
//!
//! This command takes two block hashes (competing chain tips), discovers their
//! common ancestor, fetches the payloads for both forks, and replays them
//! through the Engine API to trigger a reorg.
//!
//! The default flow is:
//! 1. **Phase 1**: Send fork A payloads and make them canonical via FCU.
//! 2. **Phase 2**: Send fork B payloads (imported as side-chain blocks).
//! 3. **Phase 3**: Send a single FCU switching the head to fork B (triggers the reorg).
//!
//! Use `--order b-then-a` to reverse which fork is built first.

use crate::{
    authenticated_transport::AuthenticatedTransportConnect,
    valid_payload::{
        block_to_new_payload, call_forkchoice_updated_with_reth, call_new_payload_with_reth,
    },
};
use alloy_primitives::B256;
use alloy_provider::{
    network::{AnyNetwork, AnyRpcBlock},
    Provider, RootProvider,
};
use alloy_rpc_client::ClientBuilder;
use alloy_rpc_types_engine::{ForkchoiceState, JwtSecret};
use alloy_transport::layers::{RateLimitRetryPolicy, RetryBackoffLayer};
use clap::{Parser, ValueEnum};
use eyre::Context;
use reth_cli_runner::CliContext;
use std::time::{Duration, Instant};
use tracing::info;
use url::Url;

/// Maximum ancestor search depth to prevent unbounded RPC walks.
const DEFAULT_MAX_DEPTH: u64 = 4096;

/// `reth bench replay-reorg` command
///
/// Replays a reorg between two block hashes by discovering the common ancestor,
/// building one fork as canonical, then importing the competing fork and switching
/// the head via forkchoiceUpdated.
///
/// Example:
///
/// `reth-bench replay-reorg --rpc-url http://localhost:8545 --engine-rpc-url
/// http://localhost:8551 --jwt-secret ~/.local/share/reth/mainnet/jwt.hex
/// --tip-a 0xaaa... --tip-b 0xbbb...`
#[derive(Debug, Parser)]
pub struct Command {
    /// Block hash of the first fork tip (initially made canonical).
    #[arg(long, value_name = "HASH")]
    tip_a: B256,

    /// Block hash of the second fork tip (triggers the reorg).
    #[arg(long, value_name = "HASH")]
    tip_b: B256,

    /// Which fork to make canonical first.
    #[arg(long, value_enum, default_value = "a-then-b")]
    order: ReorgOrder,

    /// Whether to send an FCU after every newPayload in the canonical phase,
    /// or only once at the tip.
    #[arg(long, value_enum, default_value = "tip-only")]
    fcu_mode: FcuMode,

    /// Maximum number of blocks to walk back when searching for the common ancestor.
    #[arg(long, default_value_t = DEFAULT_MAX_DEPTH)]
    max_depth: u64,

    /// The RPC URL to use for fetching block data.
    #[arg(long, value_name = "RPC_URL")]
    rpc_url: String,

    /// The engine RPC URL (with JWT authentication).
    #[arg(long, value_name = "ENGINE_RPC_URL", default_value = "http://localhost:8551")]
    engine_rpc_url: String,

    /// Path to the JWT secret file for engine API authentication.
    #[arg(long, value_name = "JWT_SECRET")]
    jwt_secret: PathBuf,

    /// Use `reth_newPayload` endpoint instead of `engine_newPayload*`.
    #[arg(long, default_value = "false")]
    reth_new_payload: bool,
}

/// Which fork to build as canonical first.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum ReorgOrder {
    /// Build fork A canonical first, then reorg to fork B.
    #[value(name = "a-then-b")]
    AThenB,
    /// Build fork B canonical first, then reorg to fork A.
    #[value(name = "b-then-a")]
    BThenA,
}

/// FCU strategy during the canonical build phase.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum FcuMode {
    /// Send a single FCU at the tip of the canonical fork.
    #[value(name = "tip-only")]
    TipOnly,
    /// Send an FCU after every newPayload in the canonical phase.
    #[value(name = "per-block")]
    PerBlock,
}

use std::path::PathBuf;

/// A fetched block with its hash and number.
struct FetchedBlock {
    block: AnyRpcBlock,
    hash: B256,
    number: u64,
    parent_hash: B256,
}

impl Command {
    /// Execute the `replay-reorg` command.
    pub async fn execute(self, _ctx: CliContext) -> eyre::Result<()> {
        info!(
            target: "reth-bench",
            tip_a = %self.tip_a,
            tip_b = %self.tip_b,
            ?self.order,
            ?self.fcu_mode,
            "Starting reorg replay"
        );

        // Set up block provider (RPC for fetching block data)
        let retry_policy =
            RateLimitRetryPolicy::default().or(|err: &alloy_transport::TransportError| -> bool {
                err.as_transport_err()
                    .and_then(|t| t.as_http_error())
                    .is_some_and(|e| e.status == 502)
            });
        let client = ClientBuilder::default()
            .layer(RetryBackoffLayer::new_with_policy(10, 800, u64::MAX, retry_policy))
            .http(self.rpc_url.parse()?);
        let block_provider = RootProvider::<AnyNetwork>::new(client);

        // Set up authenticated engine provider
        let jwt =
            std::fs::read_to_string(&self.jwt_secret).wrap_err("Failed to read JWT secret file")?;
        let jwt = JwtSecret::from_hex(jwt.trim())?;
        let auth_url = Url::parse(&self.engine_rpc_url)?;
        info!(target: "reth-bench", "Connecting to Engine RPC at {}", auth_url);
        let auth_transport = AuthenticatedTransportConnect::new(auth_url, jwt);
        let auth_client = ClientBuilder::default().connect_with(auth_transport).await?;
        let auth_provider = RootProvider::<AnyNetwork>::new(auth_client);

        // Detect optimism by checking predeploy code
        let is_optimism = !block_provider
            .get_code_at(alloy_primitives::address!("0x420000000000000000000000000000000000000F"))
            .await?
            .is_empty();

        // Phase 0: Discover common ancestor and build fork segments
        let (ancestor, fork_a_blocks, fork_b_blocks) = self.find_forks(&block_provider).await?;

        info!(
            target: "reth-bench",
            ancestor_hash = %ancestor.hash,
            ancestor_number = ancestor.number,
            fork_a_length = fork_a_blocks.len(),
            fork_b_length = fork_b_blocks.len(),
            "Discovered common ancestor"
        );

        // Determine order
        let (canonical_blocks, competing_blocks, canonical_label, competing_label) =
            match self.order {
                ReorgOrder::AThenB => (fork_a_blocks, fork_b_blocks, "A", "B"),
                ReorgOrder::BThenA => (fork_b_blocks, fork_a_blocks, "B", "A"),
            };

        let canonical_tip = canonical_blocks.last().map(|b| b.hash).unwrap_or(ancestor.hash);
        let competing_tip = competing_blocks.last().map(|b| b.hash).unwrap_or(ancestor.hash);

        // Phase 1: Build canonical fork
        info!(
            target: "reth-bench",
            fork = canonical_label,
            blocks = canonical_blocks.len(),
            "Phase 1: Building canonical fork"
        );

        let phase1_start = Instant::now();
        let mut parent_hash = ancestor.hash;

        for (i, fetched) in canonical_blocks.iter().enumerate() {
            let (version, params) = block_to_new_payload(
                fetched.block.clone(),
                is_optimism,
                None,
                self.reth_new_payload,
            )?;
            let start = Instant::now();
            call_new_payload_with_reth(&auth_provider, version, params).await?;
            let np_latency = start.elapsed();

            info!(
                target: "reth-bench",
                phase = 1,
                fork = canonical_label,
                progress = format_args!("{}/{}", i + 1, canonical_blocks.len()),
                block_number = fetched.number,
                block_hash = %fetched.hash,
                new_payload_latency = ?np_latency,
                "Sent newPayload"
            );

            // Send FCU per block if configured
            if matches!(self.fcu_mode, FcuMode::PerBlock) {
                let fcu_state = ForkchoiceState {
                    head_block_hash: fetched.hash,
                    safe_block_hash: parent_hash,
                    finalized_block_hash: ancestor.hash,
                };
                let fcu_start = Instant::now();
                call_forkchoice_updated_with_reth(&auth_provider, version, fcu_state).await?;
                info!(
                    target: "reth-bench",
                    fcu_latency = ?fcu_start.elapsed(),
                    "Sent per-block FCU"
                );
            }

            parent_hash = fetched.hash;
        }

        // Send canonical tip FCU (always, even in per-block mode, to ensure tip is canonical)
        let canonical_fcu_state = ForkchoiceState {
            head_block_hash: canonical_tip,
            safe_block_hash: ancestor.hash,
            finalized_block_hash: ancestor.hash,
        };

        // Use the version from the last canonical block, or fall back
        let canonical_version = if !canonical_blocks.is_empty() {
            let last = canonical_blocks.last().unwrap();
            block_to_new_payload(last.block.clone(), is_optimism, None, self.reth_new_payload)?.0
        } else {
            None
        };

        let fcu_start = Instant::now();
        call_forkchoice_updated_with_reth(&auth_provider, canonical_version, canonical_fcu_state)
            .await?;
        let phase1_fcu_latency = fcu_start.elapsed();
        let phase1_total = phase1_start.elapsed();

        info!(
            target: "reth-bench",
            fork = canonical_label,
            canonical_tip = %canonical_tip,
            fcu_latency = ?phase1_fcu_latency,
            total_phase_time = ?phase1_total,
            "Phase 1 complete: canonical fork built"
        );

        // Phase 2: Import competing fork blocks (newPayload only, no FCU)
        info!(
            target: "reth-bench",
            fork = competing_label,
            blocks = competing_blocks.len(),
            "Phase 2: Importing competing fork blocks"
        );

        let phase2_start = Instant::now();
        let mut phase2_np_latencies = Vec::with_capacity(competing_blocks.len());

        for (i, fetched) in competing_blocks.iter().enumerate() {
            let (version, params) = block_to_new_payload(
                fetched.block.clone(),
                is_optimism,
                None,
                self.reth_new_payload,
            )?;
            let start = Instant::now();
            call_new_payload_with_reth(&auth_provider, version, params).await?;
            let np_latency = start.elapsed();
            phase2_np_latencies.push(np_latency);

            info!(
                target: "reth-bench",
                phase = 2,
                fork = competing_label,
                progress = format_args!("{}/{}", i + 1, competing_blocks.len()),
                block_number = fetched.number,
                block_hash = %fetched.hash,
                new_payload_latency = ?np_latency,
                "Sent newPayload (side chain)"
            );
        }

        let phase2_total = phase2_start.elapsed();
        info!(
            target: "reth-bench",
            fork = competing_label,
            total_phase_time = ?phase2_total,
            "Phase 2 complete: competing fork imported"
        );

        // Phase 3: Trigger reorg via FCU to competing tip
        info!(
            target: "reth-bench",
            competing_tip = %competing_tip,
            "Phase 3: Triggering reorg"
        );

        let reorg_fcu_state = ForkchoiceState {
            head_block_hash: competing_tip,
            safe_block_hash: ancestor.hash,
            finalized_block_hash: ancestor.hash,
        };

        let competing_version = if !competing_blocks.is_empty() {
            let last = competing_blocks.last().unwrap();
            block_to_new_payload(last.block.clone(), is_optimism, None, self.reth_new_payload)?.0
        } else {
            None
        };

        let reorg_fcu_start = Instant::now();
        call_forkchoice_updated_with_reth(&auth_provider, competing_version, reorg_fcu_state)
            .await?;
        let reorg_fcu_latency = reorg_fcu_start.elapsed();

        // Summary
        let phase2_np_total: Duration = phase2_np_latencies.iter().sum();

        info!(
            target: "reth-bench",
            ancestor_number = ancestor.number,
            ancestor_hash = %ancestor.hash,
            canonical_fork = canonical_label,
            canonical_fork_length = canonical_blocks.len(),
            competing_fork = competing_label,
            competing_fork_length = competing_blocks.len(),
            phase1_canonical_build = ?phase1_total,
            phase2_competing_import = ?phase2_total,
            phase2_np_total = ?phase2_np_total,
            reorg_fcu_latency = ?reorg_fcu_latency,
            total_time = ?(phase1_total + phase2_total + reorg_fcu_latency),
            "Reorg replay complete"
        );

        Ok(())
    }

    /// Walk both tips back to their common ancestor and return the ancestor
    /// block plus the two fork segments in chronological order (ancestor-child → tip).
    async fn find_forks(
        &self,
        provider: &RootProvider<AnyNetwork>,
    ) -> eyre::Result<(FetchedBlock, Vec<FetchedBlock>, Vec<FetchedBlock>)> {
        let fetch_block = |hash: B256| async move {
            let block = provider
                .get_block_by_hash(hash)
                .full()
                .await?
                .ok_or_else(|| eyre::eyre!("Block not found: {hash}"))?;
            let number = block.header.number;
            let parent_hash = block.header.parent_hash;
            Ok::<_, eyre::Error>(FetchedBlock { block, hash, number, parent_hash })
        };

        // Fetch both tips
        let (mut a, mut b) = tokio::try_join!(fetch_block(self.tip_a), fetch_block(self.tip_b))?;

        let mut fork_a_blocks = vec![];
        let mut fork_b_blocks = vec![];
        let mut depth = 0u64;

        // Align heights: walk the higher tip down
        while a.number > b.number {
            if depth >= self.max_depth {
                return Err(eyre::eyre!(
                    "Exceeded max depth ({}) while aligning heights",
                    self.max_depth
                ));
            }
            fork_a_blocks.push(a);
            a = fetch_block(fork_a_blocks.last().unwrap().parent_hash).await?;
            depth += 1;
        }

        while b.number > a.number {
            if depth >= self.max_depth {
                return Err(eyre::eyre!(
                    "Exceeded max depth ({}) while aligning heights",
                    self.max_depth
                ));
            }
            fork_b_blocks.push(b);
            b = fetch_block(fork_b_blocks.last().unwrap().parent_hash).await?;
            depth += 1;
        }

        // Walk both back together until hashes match
        while a.hash != b.hash {
            if depth >= self.max_depth {
                return Err(eyre::eyre!(
                    "Exceeded max depth ({}) while searching for common ancestor",
                    self.max_depth
                ));
            }
            let a_parent = a.parent_hash;
            let b_parent = b.parent_hash;
            fork_a_blocks.push(a);
            fork_b_blocks.push(b);
            let (new_a, new_b) = tokio::try_join!(fetch_block(a_parent), fetch_block(b_parent))?;
            a = new_a;
            b = new_b;
            depth += 2;
        }

        // `a` and `b` are the same block (the ancestor).
        // Reverse fork segments to get chronological order (ancestor-child → tip).
        fork_a_blocks.reverse();
        fork_b_blocks.reverse();

        Ok((a, fork_a_blocks, fork_b_blocks))
    }
}
