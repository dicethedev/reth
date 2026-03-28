use super::helpers::{load_jwt_secret, read_input};
use crate::payload_converter::PayloadConverter;
use alloy_provider::network::AnyRpcBlock;
use clap::Parser;
use eyre::{OptionExt, Result};
use reth_cli_runner::CliContext;
use std::io::Write;

/// Command for generating and sending an `engine_newPayload` request constructed from an RPC
/// block.
#[derive(Debug, Parser)]
pub struct Command {
    /// Path to the json file to parse. If not specified, stdin will be used.
    #[arg(short, long)]
    path: Option<String>,

    /// The engine RPC url to use.
    #[arg(
        short,
        long,
        // Required if `mode` is `execute` or `cast`.
        required_if_eq_any([("mode", "execute"), ("mode", "cast")]),
        // If `mode` is not specified, then `execute` is used, so we need to require it.
        required_unless_present("mode")
    )]
    rpc_url: Option<String>,

    /// The JWT secret to use. Can be either a path to a file containing the secret or the secret
    /// itself.
    #[arg(short, long)]
    jwt_secret: Option<String>,

    #[arg(long, default_value_t = 3)]
    new_payload_version: u8,

    /// The mode to use.
    #[arg(long, value_enum, default_value = "execute")]
    mode: Mode,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum Mode {
    /// Execute the `cast` command. This works with blocks of any size, because it pipes the
    /// payload into the `cast` command.
    Execute,
    /// Print the `cast` command. Caution: this may not work with large blocks because of the
    /// command length limit.
    Cast,
    /// Print the JSON payload. Can be piped into `cast` command if the block is small enough.
    Json,
}

impl Command {
    /// Execute the generate payload command
    pub async fn execute<C: PayloadConverter>(self, _ctx: CliContext, converter: &C) -> Result<()> {
        // Load block
        let block_json = read_input(self.path.as_deref())?;

        // Load JWT secret
        let jwt_secret = load_jwt_secret(self.jwt_secret.as_deref())?;

        // Parse the block
        let block = serde_json::from_str::<AnyRpcBlock>(&block_json)?;

        let (payload, sidecar) = converter.block_to_payload(block)?;
        let (version, params, _execution_data) =
            converter.payload_to_new_payload(payload, sidecar, None)?;

        let json_request = serde_json::to_string(&params)?;
        let method = version.method_name();

        // Print output or execute command
        match self.mode {
            Mode::Execute => {
                // Create cast command
                let mut command = std::process::Command::new("cast");
                command.arg("rpc").arg(method).arg("--raw");
                if let Some(rpc_url) = self.rpc_url {
                    command.arg("--rpc-url").arg(rpc_url);
                }
                if let Some(secret) = &jwt_secret {
                    command.arg("--jwt-secret").arg(secret);
                }

                // Start cast process
                let mut process = command.stdin(std::process::Stdio::piped()).spawn()?;

                // Write to cast's stdin
                process
                    .stdin
                    .take()
                    .ok_or_eyre("stdin not available")?
                    .write_all(json_request.as_bytes())?;

                // Wait for cast to finish
                process.wait()?;
            }
            Mode::Cast => {
                let mut cmd = format!("cast rpc {} --raw '{}'", method, json_request);

                if let Some(rpc_url) = self.rpc_url {
                    cmd += &format!(" --rpc-url {rpc_url}");
                }
                if let Some(secret) = &jwt_secret {
                    cmd += &format!(" --jwt-secret {secret}");
                }

                println!("{cmd}");
            }
            Mode::Json => {
                println!("{json_request}");
            }
        }

        Ok(())
    }
}
