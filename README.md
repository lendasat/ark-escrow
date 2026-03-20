# ark-escrow

2-of-3 Bitcoin escrow contracts on [Arkade](https://arkade.co) (Ark protocol).

This SDK provides primitives for building escrow applications where any two of three parties (e.g. buyer, seller, arbiter) can collaboratively spend funds, with unilateral exit paths via CSV timelock.

## Architecture

### Taproot contract (6 leaves)

**Collaborative paths** (include Arkade server signature):
- Alice + Arbiter + Server — arbiter-assisted refund
- Bob + Arbiter + Server — arbiter-assisted release (happy path)
- Alice + Bob + Server — mutual settlement

**Unilateral paths** (CSV delay, no server needed):
- CSV + Alice + Arbiter — unilateral refund
- CSV + Bob + Arbiter — unilateral release
- CSV + Alice + Bob — unilateral mutual settlement

## Rust crate (`ark-escrow`)

```toml
[dependencies]
ark-escrow = { git = "https://github.com/lendasat/ark-escrow" }
```

### Core types

- **`EscrowContract`** — builds the taproot tree from 4 public keys + CSV delay
- **`EscrowClient`** — wraps Arkade gRPC (connect, find VTXO, submit, finalize)
- **`build_release_tx`** / **`build_refund_tx`** — construct unsigned PSBTs
- **`sign_ark_tx`** / **`sign_checkpoint`** — Schnorr signing helpers
- **`merge_ark_tx_sigs`** — merge signatures from multiple parties

### Example

```rust
use ark_escrow::{contract::{EscrowContract, EscrowOptions}, client::EscrowClient, spend};

// 1. Create contract
let contract = EscrowContract::new(EscrowOptions {
    alice, bob, arbiter, server,
    unilateral_exit_delay: bitcoin::Sequence::from_height(144),
}, Network::Bitcoin)?;

// 2. Connect to Arkade and find the funded VTXO
let mut client = EscrowClient::new("https://arkade.computer:7070");
let info = client.connect().await?;
let vtxo = client.find_escrow_vtxo(&contract).await?;

// 3. Build release transaction
let release = spend::build_release_tx(&contract, &vtxo, &bob_addr, fee, info)?;

// 4. Sign (each party signs independently)
spend::sign_ark_tx(&mut release.ark_tx, &bob_keypair)?;
spend::sign_ark_tx(&mut arbiter_copy, &arbiter_keypair)?;
spend::merge_ark_tx_sigs(&mut release.ark_tx, &arbiter_copy)?;

// 5. Submit and finalize
let result = client.submit(release.ark_tx, release.checkpoint_txs).await?;
// ... sign checkpoints, then finalize
```

## Ruby gem (`ark_escrow`)

Native extension providing the same primitives to Ruby via FFI.

### Build

```bash
cargo build --release -p ark-escrow-ruby
# Symlink the shared library
ln -sf target/release/libark_escrow_ruby.so target/release/ark_escrow_ruby.so  # Linux
ln -sf target/release/libark_escrow_ruby.dylib target/release/ark_escrow_ruby.bundle  # macOS
```

### Usage

```ruby
require 'ark_escrow'

# Connect to Arkade
client = ArkEscrow::Client.new("https://arkade.computer:7070")
client.connect

# Create contract
contract = ArkEscrow::Contract.new(
  alice_pk, bob_pk, arbiter_pk, client.server_pk,
  client.unilateral_exit_delay, "bitcoin"
)

# Find funded VTXO
outpoint, amount = client.find_escrow_vtxo(contract)

# Build release
ark_tx_b64, checkpoint_b64s = client.build_release(
  contract, outpoint, amount, bob_dest_address, fee_address, fee_sats
)

# Sign and merge
signed = ArkEscrow.sign_ark_tx(ark_tx_b64, secret_key_hex)
merged = ArkEscrow.merge_sigs(signed, other_signed)

# Submit and finalize
server_checkpoints = client.submit_release(merged, checkpoint_b64s)
client.finalize_release(ark_txid, signed_checkpoints)
```

## Protocol

See [docs/protocol.md](docs/protocol.md) for the full PSBT exchange protocol.
