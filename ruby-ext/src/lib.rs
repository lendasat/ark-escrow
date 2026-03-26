use std::sync::Mutex;

use ark_escrow::client::EscrowClient;
use ark_escrow::contract::{EscrowContract, EscrowOptions};
use ark_escrow::delegate::{self, DelegateVtxo};
use ark_escrow::spend;
use ark_escrow::spend_store::FileSpendStore;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{Amount, Network, Psbt, XOnlyPublicKey};
use magnus::prelude::*;
use magnus::{Error, Ruby, function, method};
use tokio::runtime::Runtime;

// --- helpers ---

fn to_magnus_err(e: impl std::fmt::Display) -> Error {
    #[allow(deprecated)]
    // Use debug formatting to get the full anyhow error chain
    Error::new(magnus::exception::runtime_error(), format!("{e:#}"))
}

fn hex_to_32_bytes(hex: &str) -> Result<[u8; 32], Error> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(to_magnus_err(format!(
            "expected 64 hex chars, got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(to_magnus_err)?;
        out[i] = u8::from_str_radix(s, 16).map_err(to_magnus_err)?;
    }
    Ok(out)
}

fn parse_xonly(hex: &str) -> Result<XOnlyPublicKey, Error> {
    let bytes = hex_to_32_bytes(hex)?;
    XOnlyPublicKey::from_slice(&bytes).map_err(to_magnus_err)
}

fn parse_network(s: &str) -> Result<Network, Error> {
    match s {
        "mainnet" | "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "signet" | "mutinynet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(to_magnus_err(format!("unknown network: {s}"))),
    }
}

fn parse_secret_key(hex: &str) -> Result<Keypair, Error> {
    let secp = Secp256k1::new();
    let bytes = hex_to_32_bytes(hex)?;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&bytes).map_err(to_magnus_err)?;
    Ok(Keypair::from_secret_key(&secp, &sk))
}

fn psbt_to_base64(psbt: &Psbt) -> String {
    use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(psbt.serialize())
}

fn psbt_from_base64(s: &str) -> Result<Psbt, Error> {
    use bitcoin::base64::{Engine, engine::general_purpose::STANDARD};
    let bytes = STANDARD.decode(s).map_err(to_magnus_err)?;
    Psbt::deserialize(&bytes).map_err(to_magnus_err)
}

// --- Ruby wrappers ---

/// Ruby class: `ArkEscrow::Contract`
#[magnus::wrap(class = "ArkEscrow::Contract")]
struct RbContract {
    inner: EscrowContract,
}

impl RbContract {
    fn new(
        alice_pk: String,
        bob_pk: String,
        arbiter_pk: String,
        server_pk: String,
        unilateral_exit_delay: u32,
        network: String,
    ) -> Result<Self, Error> {
        let opts = EscrowOptions {
            alice: parse_xonly(&alice_pk)?,
            bob: parse_xonly(&bob_pk)?,
            arbiter: parse_xonly(&arbiter_pk)?,
            server: parse_xonly(&server_pk)?,
            // Match Arkade's parse_sequence_number convention:
            // values < 512 → block-based, values >= 512 → seconds-based
            unilateral_exit_delay: if unilateral_exit_delay < 512 {
                bitcoin::Sequence::from_height(unilateral_exit_delay as u16)
            } else {
                bitcoin::Sequence::from_seconds_ceil(unilateral_exit_delay)
                    .map_err(to_magnus_err)?
            },
        };
        let net = parse_network(&network)?;
        let contract = EscrowContract::new(opts, net).map_err(to_magnus_err)?;
        Ok(Self { inner: contract })
    }

    fn address(&self) -> String {
        self.inner.address().to_string()
    }
}

/// Ruby class: `ArkEscrow::Client`
///
/// Uses a persistent tokio runtime so the gRPC connection stays alive
/// across calls (a new runtime per call would invalidate the channel).
#[magnus::wrap(class = "ArkEscrow::Client")]
struct RbClient {
    inner: Mutex<EscrowClient>,
    store: FileSpendStore,
    rt: Runtime,
}

impl RbClient {
    /// Create a new client.
    ///
    /// - `url`: Arkade gRPC URL.
    /// - `store_dir`: directory for persisting pending spends (crash recovery).
    fn new(url: String, store_dir: String) -> Result<Self, Error> {
        let rt = Runtime::new().map_err(to_magnus_err)?;
        let store = FileSpendStore::new(&store_dir).map_err(to_magnus_err)?;
        Ok(Self {
            inner: Mutex::new(EscrowClient::new(&url)),
            store,
            rt,
        })
    }

    fn connect(&self) -> Result<(), Error> {
        let mut client = self.inner.lock().map_err(to_magnus_err)?;
        self.rt.block_on(client.connect()).map_err(to_magnus_err)?;
        Ok(())
    }

    fn server_pk(&self) -> Result<String, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;
        Ok(bitcoin::hex::DisplayHex::to_lower_hex_string(
            &info.signer_pk.x_only_public_key().0.serialize(),
        ))
    }

    fn unilateral_exit_delay(&self) -> Result<u32, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;
        Ok(info.unilateral_exit_delay.to_consensus_u32())
    }

    /// Find the escrow VTXO. Returns [outpoint_str, amount_sats] or nil.
    fn find_escrow_vtxo(&self, contract: &RbContract) -> Result<Option<(String, u64)>, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let vtxo = self
            .rt
            .block_on(client.find_escrow_vtxo(&contract.inner))
            .map_err(to_magnus_err)?;
        Ok(vtxo.map(|v| (v.outpoint.to_string(), v.amount.to_sat())))
    }

    /// Find all unspent escrow VTXOs and check recoverability.
    ///
    /// Returns `[vtxos_array, any_recoverable]` where vtxos_array is
    /// `[[outpoint, amount_sats, is_swept], ...]`.
    #[allow(clippy::type_complexity)]
    fn find_escrow_vtxos(
        &self,
        contract: &RbContract,
    ) -> Result<(Vec<(String, u64, bool)>, bool), Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let (vtxos, any_recoverable) = self
            .rt
            .block_on(client.find_escrow_vtxos(&contract.inner))
            .map_err(to_magnus_err)?;
        let vtxo_data: Vec<(String, u64, bool)> = vtxos
            .iter()
            .map(|v| (v.outpoint.to_string(), v.amount.to_sat(), v.is_swept))
            .collect();
        Ok((vtxo_data, any_recoverable))
    }

    /// Prepare unsigned delegate release PSBTs.
    ///
    /// Returns `[intent_proof_b64, intent_message_json, forfeit_psbts_b64[], cosigner_pk_hex]`.
    fn prepare_release_delegate(
        &self,
        contract: &RbContract,
        vtxos_data: Vec<(String, u64, bool)>,
        bob_dest_address: String,
        fee_dest_address: Option<String>,
        fee_sats: Option<u64>,
        cosigner_sk_hex: String,
    ) -> Result<(String, String, Vec<String>, String), Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;

        let vtxos: Vec<DelegateVtxo> = vtxos_data
            .into_iter()
            .map(|(outpoint_str, amount_sats, is_swept)| {
                let outpoint: bitcoin::OutPoint = outpoint_str.parse().map_err(to_magnus_err)?;
                Ok(DelegateVtxo {
                    outpoint,
                    amount: Amount::from_sat(amount_sats),
                    is_swept,
                })
            })
            .collect::<Result<_, Error>>()?;

        let bob_dest: ark_core::ArkAddress = bob_dest_address.parse().map_err(to_magnus_err)?;

        let fee_dest = match (fee_dest_address, fee_sats) {
            (Some(addr), Some(sats)) => {
                let fee_addr: ark_core::ArkAddress = addr.parse().map_err(to_magnus_err)?;
                Some((fee_addr, Amount::from_sat(sats)))
            }
            _ => None,
        };

        let cosigner_kp = parse_secret_key(&cosigner_sk_hex)?;
        let cosigner_pk = cosigner_kp.public_key();

        let del = delegate::prepare_release_delegate(
            &contract.inner,
            &vtxos,
            &bob_dest,
            fee_dest.as_ref().map(|(a, s)| (a, *s)),
            cosigner_pk,
            info,
        )
        .map_err(to_magnus_err)?;

        let intent_proof_b64 = psbt_to_base64(&del.intent.proof);
        let intent_message_json = del.intent.serialize_message().map_err(to_magnus_err)?;
        let forfeit_psbts_b64: Vec<String> = del.forfeit_psbts.iter().map(psbt_to_base64).collect();
        let cosigner_pk_hex =
            bitcoin::hex::DisplayHex::to_lower_hex_string(&cosigner_pk.serialize());

        Ok((
            intent_proof_b64,
            intent_message_json,
            forfeit_psbts_b64,
            cosigner_pk_hex,
        ))
    }

    /// Execute delegate settlement. Blocks until the batch ceremony completes.
    ///
    /// Takes the fully-signed delegate PSBTs and runs the Arkade batch.
    /// Returns the commitment transaction ID (hex string).
    fn settle_delegate(
        &self,
        intent_proof_b64: String,
        intent_message_json: String,
        forfeit_psbts_b64: Vec<String>,
        cosigner_sk_hex: String,
    ) -> Result<String, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;

        let intent_proof = psbt_from_base64(&intent_proof_b64)?;
        let intent_message: ark_core::intent::IntentMessage =
            serde_json::from_str(&intent_message_json).map_err(to_magnus_err)?;
        let forfeit_psbts: Vec<Psbt> = forfeit_psbts_b64
            .iter()
            .map(|b| psbt_from_base64(b))
            .collect::<Result<_, _>>()?;

        let cosigner_kp = parse_secret_key(&cosigner_sk_hex)?;

        let delegate = ark_core::batch::Delegate {
            intent: ark_core::intent::Intent::new(intent_proof, intent_message),
            forfeit_psbts,
            delegate_cosigner_pk: cosigner_kp.public_key(),
        };

        let txid = self
            .rt
            .block_on(client.settle_delegate(delegate, cosigner_kp))
            .map_err(to_magnus_err)?;

        Ok(txid.to_string())
    }

    /// Build a release transaction. Returns the ark_tx PSBT (base64) and
    /// checkpoint PSBTs (array of base64).
    fn build_release(
        &self,
        contract: &RbContract,
        escrow_outpoint: String,
        escrow_amount_sats: u64,
        bob_dest_address: String,
        fee_dest_address: Option<String>,
        fee_sats: Option<u64>,
    ) -> Result<(String, Vec<String>), Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;

        let outpoint: bitcoin::OutPoint = escrow_outpoint.parse().map_err(to_magnus_err)?;
        let escrow_vtxo = spend::EscrowVtxo {
            outpoint,
            amount: Amount::from_sat(escrow_amount_sats),
        };

        let bob_dest: ark_core::ArkAddress = bob_dest_address.parse().map_err(to_magnus_err)?;

        let fee_dest = match (fee_dest_address, fee_sats) {
            (Some(addr), Some(sats)) => {
                let fee_addr: ark_core::ArkAddress = addr.parse().map_err(to_magnus_err)?;
                Some((fee_addr, Amount::from_sat(sats)))
            }
            _ => None,
        };

        let release = spend::build_release_tx(
            &contract.inner,
            &escrow_vtxo,
            &bob_dest,
            fee_dest.as_ref().map(|(a, s)| (a, *s)),
            info,
        )
        .map_err(to_magnus_err)?;

        let ark_tx_b64 = psbt_to_base64(&release.ark_tx);
        let checkpoints_b64: Vec<String> =
            release.checkpoint_txs.iter().map(psbt_to_base64).collect();

        Ok((ark_tx_b64, checkpoints_b64))
    }

    /// Build a refund transaction. Returns the ark_tx PSBT (base64) and
    /// checkpoint PSBTs (array of base64).
    fn build_refund(
        &self,
        contract: &RbContract,
        escrow_outpoint: String,
        escrow_amount_sats: u64,
        alice_dest_address: String,
    ) -> Result<(String, Vec<String>), Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;
        let info = client.server_info().map_err(to_magnus_err)?;

        let outpoint: bitcoin::OutPoint = escrow_outpoint.parse().map_err(to_magnus_err)?;
        let escrow_vtxo = spend::EscrowVtxo {
            outpoint,
            amount: Amount::from_sat(escrow_amount_sats),
        };

        let alice_dest: ark_core::ArkAddress = alice_dest_address.parse().map_err(to_magnus_err)?;

        let refund = spend::build_refund_tx(&contract.inner, &escrow_vtxo, &alice_dest, info)
            .map_err(to_magnus_err)?;

        let ark_tx_b64 = psbt_to_base64(&refund.ark_tx);
        let checkpoints_b64: Vec<String> =
            refund.checkpoint_txs.iter().map(psbt_to_base64).collect();

        Ok((ark_tx_b64, checkpoints_b64))
    }

    /// Spend an escrow VTXO offchain with crash recovery.
    ///
    /// Wraps the two-phase Arkade protocol (submit + finalize) with a
    /// persistence guard.
    ///
    /// - `id` — unique identifier for deduplication (e.g. trade ID).
    /// - `merged_ark_tx_b64` — ark_tx PSBT with all non-server sigs merged.
    /// - `unsigned_checkpoint_txs_b64` — raw unsigned checkpoint PSBTs.
    /// - `party_signed_checkpoints_b64` — array of arrays: each inner array is
    ///   one party's signed checkpoint PSBTs (base64).
    ///
    /// Returns the Arkade transaction ID (hex string).
    fn spend_escrow_offchain(
        &self,
        id: String,
        merged_ark_tx_b64: String,
        unsigned_checkpoint_txs_b64: Vec<String>,
        party_signed_checkpoints_b64: Vec<Vec<String>>,
    ) -> Result<String, Error> {
        let client = self.inner.lock().map_err(to_magnus_err)?;

        let merged_ark_tx = psbt_from_base64(&merged_ark_tx_b64)?;
        let unsigned_checkpoints: Vec<Psbt> = unsigned_checkpoint_txs_b64
            .iter()
            .map(|b| psbt_from_base64(b))
            .collect::<Result<_, _>>()?;

        let party_checkpoints: Vec<Vec<Psbt>> = party_signed_checkpoints_b64
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|b| psbt_from_base64(b))
                    .collect::<Result<_, _>>()
            })
            .collect::<Result<_, _>>()?;

        let party_refs: Vec<&[Psbt]> = party_checkpoints.iter().map(|v| v.as_slice()).collect();

        let txid = self
            .rt
            .block_on(client.spend_escrow_offchain(
                &self.store,
                &id,
                merged_ark_tx,
                unsigned_checkpoints,
                &party_refs,
            ))
            .map_err(to_magnus_err)?;

        Ok(txid.to_string())
    }
}

// --- Signing helpers (stateless, exposed as module functions) ---

fn rb_sign_ark_tx(psbt_b64: String, secret_key_hex: String) -> Result<String, Error> {
    let mut psbt = psbt_from_base64(&psbt_b64)?;
    let kp = parse_secret_key(&secret_key_hex)?;
    spend::sign_ark_tx(&mut psbt, &kp).map_err(to_magnus_err)?;
    Ok(psbt_to_base64(&psbt))
}

fn rb_sign_checkpoint(psbt_b64: String, secret_key_hex: String) -> Result<String, Error> {
    let mut psbt = psbt_from_base64(&psbt_b64)?;
    let kp = parse_secret_key(&secret_key_hex)?;
    spend::sign_checkpoint(&mut psbt, &kp).map_err(to_magnus_err)?;
    Ok(psbt_to_base64(&psbt))
}

/// Sign delegate PSBTs (intent + forfeits) with a single keypair.
/// Takes and returns: (intent_proof_b64, forfeit_psbts_b64[])
fn rb_sign_delegate(
    intent_proof_b64: String,
    forfeit_psbts_b64: Vec<String>,
    secret_key_hex: String,
) -> Result<(String, Vec<String>), Error> {
    let intent_proof = psbt_from_base64(&intent_proof_b64)?;
    let kp = parse_secret_key(&secret_key_hex)?;
    let secp = Secp256k1::new();
    let xonly = kp.x_only_public_key().0;

    let mut signed_intent = intent_proof;
    let mut forfeit_psbts: Vec<Psbt> = forfeit_psbts_b64
        .iter()
        .map(|b| psbt_from_base64(b))
        .collect::<Result<_, _>>()?;

    // sign_delegate_psbts handles both intent (SIGHASH_ALL) and
    // forfeit (SIGHASH_ALL|ANYONECANPAY) inputs correctly.
    ark_core::batch::sign_delegate_psbts(
        |_,
         msg: secp256k1::Message|
         -> Result<
            Vec<(bitcoin::secp256k1::schnorr::Signature, XOnlyPublicKey)>,
            ark_core::Error,
        > {
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
            Ok(vec![(sig, xonly)])
        },
        &mut signed_intent,
        &mut forfeit_psbts,
    )
    .map_err(to_magnus_err)?;

    let intent_b64 = psbt_to_base64(&signed_intent);
    let forfeits_b64: Vec<String> = forfeit_psbts.iter().map(psbt_to_base64).collect();
    Ok((intent_b64, forfeits_b64))
}

fn rb_merge_sigs(base_b64: String, other_b64: String) -> Result<String, Error> {
    let mut base = psbt_from_base64(&base_b64)?;
    let other = psbt_from_base64(&other_b64)?;
    spend::merge_ark_tx_sigs(&mut base, &other).map_err(to_magnus_err)?;
    Ok(psbt_to_base64(&base))
}

// --- Init ---

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("ArkEscrow")?;

    let contract_class = module.define_class("Contract", ruby.class_object())?;
    contract_class.define_singleton_method("new", function!(RbContract::new, 6))?;
    contract_class.define_method("address", method!(RbContract::address, 0))?;

    let client_class = module.define_class("Client", ruby.class_object())?;
    client_class.define_singleton_method("new", function!(RbClient::new, 2))?;
    client_class.define_method("connect", method!(RbClient::connect, 0))?;
    client_class.define_method("server_pk", method!(RbClient::server_pk, 0))?;
    client_class.define_method(
        "unilateral_exit_delay",
        method!(RbClient::unilateral_exit_delay, 0),
    )?;
    client_class.define_method("find_escrow_vtxo", method!(RbClient::find_escrow_vtxo, 1))?;
    client_class.define_method("find_escrow_vtxos", method!(RbClient::find_escrow_vtxos, 1))?;
    client_class.define_method("build_release", method!(RbClient::build_release, 6))?;
    client_class.define_method("build_refund", method!(RbClient::build_refund, 4))?;
    client_class.define_method(
        "spend_escrow_offchain",
        method!(RbClient::spend_escrow_offchain, 4),
    )?;
    client_class.define_method(
        "prepare_release_delegate",
        method!(RbClient::prepare_release_delegate, 6),
    )?;
    client_class.define_method("settle_delegate", method!(RbClient::settle_delegate, 4))?;

    module.define_module_function("sign_ark_tx", function!(rb_sign_ark_tx, 2))?;
    module.define_module_function("sign_checkpoint", function!(rb_sign_checkpoint, 2))?;
    module.define_module_function("merge_sigs", function!(rb_merge_sigs, 2))?;
    module.define_module_function("sign_delegate", function!(rb_sign_delegate, 3))?;

    Ok(())
}
