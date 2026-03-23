use anyhow::{Context, Result};
use ark_core::send::{self, OffchainTransactions, VtxoInput};
use ark_core::server;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, Secp256k1, schnorr};
use bitcoin::{Amount, OutPoint, Psbt, XOnlyPublicKey};

use crate::contract::EscrowContract;

/// Everything needed to describe an escrow VTXO that will be spent.
pub struct EscrowVtxo {
    /// The outpoint of the escrow VTXO on the virtual tx graph.
    pub outpoint: OutPoint,
    /// The amount locked in the escrow.
    pub amount: Amount,
}

/// The result of building an escrow spend transaction (release or refund).
///
/// Contains the ark_tx PSBT (needs signer + server sigs) and the checkpoint
/// PSBTs that will be signed after server co-signs.
pub struct EscrowTransaction {
    pub ark_tx: Psbt,
    pub checkpoint_txs: Vec<Psbt>,
}

/// Build the offchain release transaction.
///
/// Produces an ark_tx spending the escrow VTXO via the `bob_arbiter` leaf
/// (collaborative path: bob + arbiter + server). Outputs go to:
///   - Bob's destination address (escrow amount minus fee)
///   - Arbiter's fee address (if fee > 0)
///
/// The returned PSBTs are unsigned — callers collect signatures from Bob and
/// the arbiter before submitting.
pub fn build_release_tx(
    contract: &EscrowContract,
    escrow_vtxo: &EscrowVtxo,
    bob_dest: &ark_core::ArkAddress,
    fee_dest: Option<(&ark_core::ArkAddress, Amount)>,
    server_info: &server::Info,
) -> Result<EscrowTransaction> {
    let spend_script = contract.options().bob_arbiter_script();
    let control_block = contract.control_block(&spend_script)?;

    let vtxo_input = VtxoInput::new(
        spend_script,
        None, // no CLTV locktime
        control_block,
        contract.tapscripts(),
        contract.script_pubkey(),
        escrow_vtxo.amount,
        escrow_vtxo.outpoint,
    );

    let mut outputs: Vec<(&ark_core::ArkAddress, Amount)> = Vec::new();

    let bob_amount = match fee_dest {
        Some((_, fee)) => escrow_vtxo
            .amount
            .checked_sub(fee)
            .context("fee exceeds escrow amount")?,
        None => escrow_vtxo.amount,
    };
    outputs.push((bob_dest, bob_amount));

    if let Some((fee_addr, fee_amount)) = &fee_dest {
        outputs.push((fee_addr, *fee_amount));
    }

    let OffchainTransactions {
        ark_tx,
        checkpoint_txs,
    } = send::build_offchain_transactions(
        &outputs,
        None, // no change — full spend
        std::slice::from_ref(&vtxo_input),
        server_info,
    )
    .context("building release offchain transactions")?;

    Ok(EscrowTransaction {
        ark_tx,
        checkpoint_txs,
    })
}

/// Build a refund transaction (alice + arbiter path).
///
/// Returns the full escrow amount to Alice (no fee output).
pub fn build_refund_tx(
    contract: &EscrowContract,
    escrow_vtxo: &EscrowVtxo,
    alice_dest: &ark_core::ArkAddress,
    server_info: &server::Info,
) -> Result<EscrowTransaction> {
    let spend_script = contract.options().alice_arbiter_script();
    let control_block = contract.control_block(&spend_script)?;

    let vtxo_input = VtxoInput::new(
        spend_script,
        None,
        control_block,
        contract.tapscripts(),
        contract.script_pubkey(),
        escrow_vtxo.amount,
        escrow_vtxo.outpoint,
    );

    let outputs = [(alice_dest, escrow_vtxo.amount)];

    let OffchainTransactions {
        ark_tx,
        checkpoint_txs,
    } = send::build_offchain_transactions(
        &outputs,
        None,
        std::slice::from_ref(&vtxo_input),
        server_info,
    )
    .context("building refund offchain transactions")?;

    Ok(EscrowTransaction {
        ark_tx,
        checkpoint_txs,
    })
}

// --- Signing helpers ---

/// Sign the ark_tx PSBT with a single keypair (Bob or arbiter).
///
/// Adds a tapscript signature for the given key on input 0 (the escrow VTXO).
pub fn sign_ark_tx(psbt: &mut Psbt, keypair: &Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let xonly = keypair.x_only_public_key().0;

    send::sign_ark_transaction(
        |_,
         msg: secp256k1::Message|
         -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
            Ok(vec![(sig, xonly)])
        },
        psbt,
        0, // escrow VTXO is always input 0
    )
    .context("signing ark transaction")?;

    Ok(())
}

/// Sign a checkpoint PSBT with a single keypair.
pub fn sign_checkpoint(psbt: &mut Psbt, keypair: &Keypair) -> Result<()> {
    let secp = Secp256k1::new();
    let xonly = keypair.x_only_public_key().0;

    send::sign_checkpoint_transaction(
        |_,
         msg: secp256k1::Message|
         -> Result<Vec<(schnorr::Signature, XOnlyPublicKey)>, ark_core::Error> {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
            Ok(vec![(sig, xonly)])
        },
        psbt,
    )
    .context("signing checkpoint transaction")?;

    Ok(())
}

// --- Signature merging ---

/// Merge tap_script_sigs from one PSBT into another.
///
/// Takes the base PSBT (with one party's sigs) and merges sigs from another
/// copy. Both PSBTs must have the same unsigned tx.
pub fn merge_ark_tx_sigs(base: &mut Psbt, other: &Psbt) -> Result<()> {
    for (i, other_input) in other.inputs.iter().enumerate() {
        for (key, sig) in &other_input.tap_script_sigs {
            base.inputs[i]
                .tap_script_sigs
                .entry(*key)
                .or_insert_with(|| *sig);
        }
    }
    Ok(())
}
