//! Trait abstraction for chain-specific payload conversions in benchmarks.

use alloy_consensus::TxEnvelope;
use alloy_provider::network::AnyRpcBlock;
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayload, ExecutionPayloadInputV2, ExecutionPayloadSidecar,
};
use reth_node_api::EngineApiMessageVersion;

/// Converts RPC blocks into engine API payloads.
///
/// Different chains (Ethereum, Optimism, …) need different transaction/payload
/// encoding when talking to `engine_newPayload*`. Implement this trait once per
/// chain and pass it into the benchmark commands.
pub trait PayloadConverter: Send + Sync + 'static {
    /// Convert an [`AnyRpcBlock`] into an [`ExecutionPayload`] and its
    /// [`ExecutionPayloadSidecar`].
    fn block_to_payload(
        &self,
        block: AnyRpcBlock,
    ) -> eyre::Result<(ExecutionPayload, ExecutionPayloadSidecar)>;

    /// Serialize an [`ExecutionPayload`] + [`ExecutionPayloadSidecar`] into the
    /// versioned JSON params expected by the corresponding `engine_newPayload*`
    /// method, together with the assembled [`ExecutionData`].
    fn payload_to_new_payload(
        &self,
        payload: ExecutionPayload,
        sidecar: ExecutionPayloadSidecar,
        target_version: Option<EngineApiMessageVersion>,
    ) -> eyre::Result<(EngineApiMessageVersion, serde_json::Value, ExecutionData)>;
}

/// Ethereum-specific [`PayloadConverter`].
#[derive(Debug, Default, Clone, Copy)]
pub struct EthereumPayloadConverter;

impl PayloadConverter for EthereumPayloadConverter {
    fn block_to_payload(
        &self,
        block: AnyRpcBlock,
    ) -> eyre::Result<(ExecutionPayload, ExecutionPayloadSidecar)> {
        let block = block
            .into_inner()
            .map_header(|header| header.map(|h| h.into_header_with_defaults()))
            .try_map_transactions(|tx| -> eyre::Result<TxEnvelope> {
                tx.try_into().map_err(|_| eyre::eyre!("unsupported tx type"))
            })?
            .into_consensus();

        Ok(ExecutionPayload::from_block_slow(&block))
    }

    fn payload_to_new_payload(
        &self,
        payload: ExecutionPayload,
        sidecar: ExecutionPayloadSidecar,
        target_version: Option<EngineApiMessageVersion>,
    ) -> eyre::Result<(EngineApiMessageVersion, serde_json::Value, ExecutionData)> {
        let execution_data = ExecutionData { payload: payload.clone(), sidecar: sidecar.clone() };

        let (version, params) = match payload {
            ExecutionPayload::V3(payload) => {
                let cancun = sidecar
                    .cancun()
                    .ok_or_else(|| eyre::eyre!("missing cancun sidecar for V3 payload"))?;

                if let Some(prague) = sidecar.prague() {
                    let version = target_version.unwrap_or(EngineApiMessageVersion::V4);
                    let requests = prague.requests.clone();
                    (
                        version,
                        serde_json::to_value((
                            payload,
                            cancun.versioned_hashes.clone(),
                            cancun.parent_beacon_block_root,
                            requests,
                        ))?,
                    )
                } else {
                    (
                        EngineApiMessageVersion::V3,
                        serde_json::to_value((
                            payload,
                            cancun.versioned_hashes.clone(),
                            cancun.parent_beacon_block_root,
                        ))?,
                    )
                }
            }
            ExecutionPayload::V2(payload) => {
                let input = ExecutionPayloadInputV2 {
                    execution_payload: payload.payload_inner,
                    withdrawals: Some(payload.withdrawals),
                };

                (EngineApiMessageVersion::V2, serde_json::to_value((input,))?)
            }
            ExecutionPayload::V1(payload) => {
                (EngineApiMessageVersion::V1, serde_json::to_value((payload,))?)
            }
        };

        Ok((version, params, execution_data))
    }
}
