# Escrow PSBT Exchange Protocol

This document describes the multi-step signing protocol for releasing or refunding an escrow VTXO on Arkade.

## Parties

| Party | Role |
|-------|------|
| **Alice** | Escrow funder (buyer) |
| **Bob** | Escrow recipient (seller) |
| **Arbiter** | Trusted mediator (e.g. platform operator) |
| **Arkade Server** | Co-signer for collaborative paths |

## Contract Setup

1. Alice and Bob exchange public keys
2. The arbiter provides its public key
3. An `EscrowContract` is created with all 4 public keys + CSV delay
4. Alice funds the resulting Arkade address (the escrow VTXO)

## Release Flow (Happy Path)

The release uses the **Bob + Arbiter + Server** collaborative leaf.

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌────────┐
│  Bob    │     │ Arbiter  │     │  Server  │     │ Arkade │
│(browser)│     │(backend) │     │  (gRPC)  │     │        │
└────┬────┘     └────┬─────┘     └────┬─────┘     └───┬────┘
     │               │               │               │
     │  1. Request release            │               │
     │──────────────>│               │               │
     │               │               │               │
     │               │ 2. build_release_tx()          │
     │               │ 3. sign_ark_tx(arbiter_sk)     │
     │               │               │               │
     │  4. Return arbiter-signed PSBT │               │
     │<──────────────│               │               │
     │               │               │               │
     │ 5. sign_ark_tx(bob_sk)        │               │
     │ 6. Send bob-signed PSBT       │               │
     │──────────────>│               │               │
     │               │               │               │
     │               │ 7. merge_sigs(arbiter, bob)    │
     │               │ 8. submit(merged, checkpoints) │
     │               │──────────────────────────────>│
     │               │               │               │
     │               │ 9. Server-signed checkpoints   │
     │               │<──────────────────────────────│
     │               │               │               │
     │               │ 10. sign_checkpoint(arbiter_sk)│
     │  11. Return arbiter-signed checkpoints         │
     │<──────────────│               │               │
     │               │               │               │
     │ 12. sign_checkpoint(bob_sk)   │               │
     │ 13. Send bob-signed checkpoints│               │
     │──────────────>│               │               │
     │               │               │               │
     │               │ 14. merge checkpoint sigs      │
     │               │ 15. finalize(txid, checkpoints)│
     │               │──────────────────────────────>│
     │               │               │               │
     │  16. Done — escrow released   │               │
     │<──────────────│               │               │
```

### Step-by-step

1. **Bob requests release** — provides his destination Arkade address
2. **Arbiter builds the release tx** — `build_release_tx()` produces unsigned `ark_tx` + `checkpoint_txs` PSBTs
3. **Arbiter signs** — `sign_ark_tx(ark_tx, arbiter_sk)` adds arbiter's tapscript signature
4. **Arbiter returns PSBTs** — sends arbiter-signed `ark_tx` + unsigned `checkpoint_txs` to Bob
5. **Bob signs the ark_tx** — `sign_ark_tx(ark_tx, bob_sk)` or equivalent in TS
6. **Bob returns signed ark_tx** to the arbiter
7. **Arbiter merges signatures** — `merge_ark_tx_sigs(arbiter_signed, bob_signed)`
8. **Arbiter submits to Arkade** — `submit(merged_ark_tx, checkpoint_txs)` via gRPC
9. **Arkade returns server-signed checkpoints** — server adds its signatures
10. **Arbiter signs checkpoints** — `sign_checkpoint(cp, arbiter_sk)` for each
11. **Arbiter returns checkpoints** to Bob for co-signing
12. **Bob signs checkpoints** — `sign_checkpoint(cp, bob_sk)` or equivalent in TS
13. **Bob returns signed checkpoints**
14. **Arbiter merges checkpoint sigs** — `merge_ark_tx_sigs(arbiter_cp, bob_cp)` for each
15. **Arbiter finalizes** — `finalize(ark_txid, merged_checkpoints)` via gRPC
16. **Done** — escrow VTXO is spent, Bob receives funds at destination

## Refund Flow

Same protocol but uses the **Alice + Arbiter + Server** collaborative leaf via `build_refund_tx()`. Alice signs instead of Bob, and funds return to Alice's address.

## Unilateral Exit

If the Arkade server is unavailable, any collaborative path can be replaced by its unilateral counterpart after the CSV delay expires. The unilateral paths require only 2 of the 3 user parties (no server signature needed).

## PSBT Format

- All PSBTs are exchanged as **base64-encoded strings**
- The ark_tx PSBT always has the escrow VTXO as **input 0**
- Signatures are **Schnorr tapscript signatures** (BIP 341)
- Merging combines `tap_script_sigs` from both PSBTs

## TypeScript (Frontend) Signing

Frontend clients sign using `@arkade-os/sdk`:

```typescript
import { Transaction } from "@arkade-os/sdk";

// Sign ark_tx
const tx = Transaction.fromPSBT(base64ToBytes(psbtB64));
tx.signIdx(secretKey, 0);
const signed = bytesToBase64(tx.toPSBT());

// Sign checkpoint
const cp = Transaction.fromPSBT(base64ToBytes(cpB64));
cp.signIdx(secretKey, 0);
const signedCp = bytesToBase64(cp.toPSBT());
```

The `@lendasat/lendaswap-sdk-pure` package provides `signEscrowArkTx()`, `signEscrowCheckpoints()`, and `getArkTxid()` helpers for this.
