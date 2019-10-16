// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # LibWallet API Definition
//!
//! This module contains the Rust backend implementations of the functionality that a wallet for the Tari Base Layer
//! will require. The module contains a number of sub-modules that are implemented as async services. These services are
//! collected into the main Wallet container struct which manages spinning up all the component services and maintains a
//! collection of the handles required to interact with those services.
//!
//! This docstring serves to document the API calls that will be exposed to external systems that make use of this
//! module. The API will be exposed via FFI.
//!
//! ## API Calls
//!
//! ### `generate_master_seed(branch_seed: String) -> ()`
//! Generate a master private key using the provided `branch_seed` for an extra passphrase for security OR to specify
//! this keychain for a specific device
//!
//! ### `get_seed_words() -> Vec<String>`
//! Get the seed words that represent the current master seed in use on this wallet
//!
//! ### `generate_node_id() -> NodeIdentity`
//! Generate a new node identity for use on the Tari P2P network
//!
//! ### `get_node_id() -> Result<NodeIdentity, WalletError>`
//! Get the currently set node identity
//!
//! ### `set_base_node(config: BaseNodeConfig) -> Result<(), WalletError>`
//! Provide the network configuration of the Base Node that this Wallet will utilize
//!
//! ### `get_network_status() -> NetworkStatus`
//! Provides the current status of the wallets network connection to base nodes and peers
//!
//! ### `send_new_transaction(destination_node_id: NodeIdentity, amount: MicroTari, fee_per_gram: MicroTari) ->
//! ### Result<TxId, WalletError>`
//! Create and send the first stage of a transaction to the specified wallet for the specified amount and with the
//! specified fee.
//!
//! ### 'cancel_transaction(id: TxId) -> Result<(), WalletError>
//! Cancel a pending outbound transaction so that the wallet will not complete and broadcast it if a reply is received.
//!
//! ### `get_pending_transactions() -> Result<Vec<PendingTransactionData>, WalletError>`
//! Retrieve the full list of pending transactions, both outbound and inbound.
//!
//! ### `get_completed_transactions() -> Result<Vec<CompletedTransactionData>, WalletError>`
//! Retrieve the full list of completed transactions
//!
//! ### `get_balance() -> MicroTari`
//! Get the current balance of unspent outputs
//!
//! ### `add_unspent_output(output: UnblindedOutput) -> ()`
//! Add an unspent output from an external source to this wallets ledger
//!
//! ### `get_unspent_outputs() -> Vec<UnblindedOutput>`
//! *QUESTION:* Should the returned value here include the private key?
//!
//! ### `get_spent_outputs() -> Vec<UnblindedOutput>`
//! *QUESTION:* Should the returned value here include the private key?
//!
//! ## Outgoing FFI calls
//! These calls will need to be supported by the client using LibWallet i.e. LibWallet will make these calls to the
//! client system. All of these calls are to store and retrieve this data in the persistence provided by the client
//! device.
//!
//! ### `set_key_manager_data(master_seed: PrivateKey, branch_seed: String, index: usize)`
//! Store the data required to produce this keychain.
//!
//! ### `get_master_seed() -> Result<KeyManagerData, WalletError>`
//!
//! ### `set_network_config(config: NetworkConfig)`
//! Store the current network config including this nodes identity and peers
//!
//! ### `get_network_config() -> Result<NetworkConfig, WalletError>`
//!
//! ### `set_base_node_config(config: BaseNodeConfig)`
//! Store the current config of the base nodes that this wallet will connect to.
//!
//! ### `get_base_node_config() -> Result<BaseNodeConfig, WalletError>`
//!
//! ### `set_pending_inbound_transaction(tx: PendingTransactionData)`
//! Store a pending inbound transaction.
//!
//! ### `get_pending_inbound_transaction(id: TxId) -> Result<PendingInboundTransaction, WalletError>`
//!
//! ### `get_pending_inbound_transactions() -> Result<Vec<PendingTransactionData>, WalletError>`
//!
//! ### `set_pending_outbound_transaction(tx: PendingTransactionData)`
//! Store a pending outbound transaction.
//!
//! ### `get_pending_outbound_transaction(id: TxId) -> Result<PendingOutboundTransaction, WalletError>`
//!
//! ### `get_pending_outbound_transactions() -> Result<Vec<PendingOutboundTransaction>, WalletError>`
//!
//! ### `set_completed_transaction(tx: Transaction)`
//! Store a completed transaction.
//!
//! ### `get_completed_transaction(id: TxId) -> Result<Transaction, WalletError>`
//!
//! ### `get_completed_transactions() -> Vec<Transaction>`
//!
//! ### `set_unspent_output(output: UnblindedOutput) -> ()`
//! Store an unblinded unspent output.
//!
//! ### `get_unspent_output(key: PrivateKey) -> Result<UnblindedOutput, WalletError>`
//!
//! ### `get_unspent_outputs() -> Result<Vec<UnblindedOutput>, WalletError>`
//!
//! ### `set_spent_output(output: UnblindedOutput) -> ()`
//!
//! ### `get_spent_output(key: PrivateKey) -> Result<UnblindedOutput, WalletError>`
//!
//! ### `get_spent_outputs() -> Result<Vec<UnblindedOutput>, WalletError>`
//!
//! ## Open Questions
//! - How will LibWallet join and communicate with other nodes on the network?
//!   - Base Nodes
//!   - Other Wallets
//! - Will we support adding multiple base nodes?
//! - Pagination for Transaction and Output data?
//! - Will the client apps be responsible for encryption of sensitive data for persistent storage i.e. master seed,
//!   branch seed etc?

pub mod support;
// pub mod text_message_service;
// pub mod wallet;

// TODO These were removed due to Comms layer upgrades, put back once Comms layer is stable
// pub mod transaction_service;
// pub mod output_manager_service;
