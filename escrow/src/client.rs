use std::collections::HashMap;

use anyhow::{Context, Result};
use ark_core::VtxoList;
use ark_core::server::{self, GetVtxosRequest};
use bitcoin::{Psbt, Txid};

use crate::contract::EscrowContract;
use crate::spend::EscrowVtxo;

/// Wraps an `ark_grpc::Client` with escrow-specific helpers.
pub struct EscrowClient {
    grpc: ark_grpc::Client,
    server_info: Option<server::Info>,
}

impl EscrowClient {
    pub fn new(url: &str) -> Self {
        Self {
            grpc: ark_grpc::Client::new(url.to_string()),
            server_info: None,
        }
    }

    /// Connect to the Arkade server and fetch server info.
    pub async fn connect(&mut self) -> Result<&server::Info> {
        // Ensure a TLS crypto provider is installed (needed for https:// URLs)
        let _ = rustls::crypto::ring::default_provider().install_default();
        self.grpc.connect().await.context("connecting to Arkade")?;
        let info = self.grpc.get_info().await.context("getting server info")?;
        self.server_info = Some(info);
        Ok(self.server_info.as_ref().unwrap())
    }

    pub fn server_info(&self) -> Result<&server::Info> {
        self.server_info
            .as_ref()
            .context("not connected — call connect() first")
    }

    /// Find the escrow VTXO on Arkade by looking up the contract's address.
    ///
    /// Returns the first spendable offchain VTXO matching the escrow address,
    /// or None if no funded escrow exists.
    pub async fn find_escrow_vtxo(&self, contract: &EscrowContract) -> Result<Option<EscrowVtxo>> {
        let info = self.server_info()?;
        let address = contract.address();

        let request = GetVtxosRequest::new_for_addresses(std::iter::once(address));
        let response = self
            .grpc
            .list_vtxos(request)
            .await
            .context("listing VTXOs")?;

        let vtxo_list = VtxoList::new(info.dust, response.vtxos);

        let vtxo = vtxo_list.spendable_offchain().next();

        Ok(vtxo.map(|v| EscrowVtxo {
            outpoint: v.outpoint,
            amount: v.amount,
        }))
    }

    /// Submit a signed ark_tx + checkpoint PSBTs to the Arkade server.
    ///
    /// Returns the server-signed checkpoint PSBTs. The caller must then sign
    /// these checkpoints (Bob + arbiter) and call `finalize`.
    pub async fn submit(&self, ark_tx: Psbt, checkpoint_txs: Vec<Psbt>) -> Result<SubmitResult> {
        let res = self
            .grpc
            .submit_offchain_transaction_request(ark_tx, checkpoint_txs.clone())
            .await
            .context("submitting offchain transaction")?;

        // Build a map from original checkpoint txid → witness_script so we can
        // restore witness_script on the server-returned checkpoints (the server
        // may strip it).
        let witness_scripts: HashMap<Txid, _> = checkpoint_txs
            .iter()
            .map(|cp| {
                let txid = cp.unsigned_tx.compute_txid();
                let ws = cp.inputs[0].witness_script.clone();
                (txid, ws)
            })
            .collect();

        let signed_checkpoints = res
            .signed_checkpoint_txs
            .into_iter()
            .map(|mut cp| {
                let txid = cp.unsigned_tx.compute_txid();
                if let Some(ws) = witness_scripts.get(&txid) {
                    cp.inputs[0].witness_script = ws.clone();
                }
                cp
            })
            .collect();

        Ok(SubmitResult {
            signed_ark_tx: res.signed_ark_tx,
            signed_checkpoint_txs: signed_checkpoints,
        })
    }

    /// Finalize the offchain transaction after all checkpoint signatures are
    /// collected.
    pub async fn finalize(&self, ark_txid: Txid, signed_checkpoint_txs: Vec<Psbt>) -> Result<()> {
        self.grpc
            .finalize_offchain_transaction(ark_txid, signed_checkpoint_txs)
            .await
            .context("finalizing offchain transaction")?;
        Ok(())
    }

    /// Access the underlying gRPC client.
    pub fn grpc(&self) -> &ark_grpc::Client {
        &self.grpc
    }
}

pub struct SubmitResult {
    pub signed_ark_tx: Psbt,
    pub signed_checkpoint_txs: Vec<Psbt>,
}
