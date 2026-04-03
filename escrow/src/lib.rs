use bitcoin::Amount;

pub mod client;
pub mod contract;
pub mod delegate;
pub mod spend;
pub mod spend_store;

#[derive(Clone, Copy, Debug)]
pub struct FeeOutput {
    pub address: ark_core::ArkAddress,
    pub amount: Amount,
}
