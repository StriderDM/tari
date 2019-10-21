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
//! This module contains the Rust backend implementations of the functionality that a wallet for the Tari Base Layer
//! will require. The module contains a number of sub-modules that are implemented as async services. These services are
//! collected into the main Wallet container struct which manages spinning up all the component services and maintains a
//! collection of the handles required to interact with those services.
//! This files contians the API calls that will be exposed to external systems that make use of this module. The API
//! will be exposed via FFI and will consist of API calls that the FFI client can make into the Wallet module and a set
//! of Callbacks that the client must implement and provide to the Wallet module to receive asynchronous replies and
//! updates.
extern crate libc;

use crate::{output_manager_service::service::PendingTransactionOutputs,Wallet};
use chrono::NaiveDateTime;
// use std::os::raw::{c_char, c_int, c_uint, c_ulonglong};
use libc::{c_char,c_uchar,c_int,c_uint,c_ulonglong};
use std::{
    boxed::Box,
    ffi::{CStr,CString},
    ptr
};
use tari_comms::connection::NetAddress;
use tari_core::{
    transaction::{Transaction, UnblindedOutput},
    types::{PrivateKey, PublicKey},
};
use tari_utilities::hex::Hex;
use tokio::runtime::Runtime;

pub type TariWallet = Wallet;
pub type WalletPublicKey = PrivateKey;
pub type WalletDateTime = NaiveDateTime;

/// -------------------------------- Runtime --------------------------------------------------- ///
/// Example c++ Usage
/// class TokioRuntime
/// {
/// public:
///   TokioRuntime* Instance()
///   {
///     static TokioRuntime* instance = NULL;
///
///     if (!instance)
///     {
///        TokioRuntime();
///     }
///     return instance;
/// }
/// private:
///   TokioRuntime() { instance = runtime_create(); }
///   ~TokioRuntime() { runtime_destroy(instance); }
/// }
pub type TokioRuntime = Runtime;

#[no_mangle]
pub unsafe extern "C" fn runtime_create() -> *mut TokioRuntime
{
    let mut r = TokioRuntime::new().unwrap();
    Box::into_raw(Box::new(r))
}

#[no_mangle]
pub unsafe extern "C" fn runtime_destroy(runtime: *mut TokioRuntime) {
    if !runtime.is_null() {
        Box::from_raw(runtime);
    }
}
/// -------------------------------------------------------------------------------------------- ///


/// -------------------------------- Public Key ------------------------------------------------ ///
/// Example c++ Usage
/// class PublicKey
/// {
///  public:
///    PublicKey(s:char*) { pointer = public_key_create(s); }
///    const char* Get_Hex_Str() { return public_key_get_key(pointer); }
///    ~PublicKey() { public_key_destroy(pointer); }
/// private:
///   PublicKey* pointer;
/// }

pub type WalletPrivateKey = PublicKey;

#[no_mangle]
pub unsafe extern "C" fn public_key_create(hex: *const c_char) -> *mut WalletPublicKey
{
    let str = CStr::from_ptr(hex).to_str().unwrap().to_owned();
    let pk = WalletPublicKey::from_hex(str.as_str()).unwrap();//::from_hex(str);
    Box::into_raw(Box::new(pk))
}

#[no_mangle]
pub unsafe extern "C" fn public_key_destroy(pk: *mut WalletPublicKey) {
    if !pk.is_null() {
        Box::from_raw(pk);
    }
}

#[no_mangle]
pub unsafe extern "C" fn public_key_get_key(pk: *mut WalletPublicKey) -> *mut c_char
{
    let mut result = CString::new("").unwrap();
    if !pk.is_null() {
        result = CString::new((*pk).to_hex()).unwrap();
    }
    CString::into_raw(result)
}

/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- Private Key ------------------------------------------------ ///
/// Example c++ Usage
/// class PrivateKey
/// {
///  public:
///    PrivateKey(s:char*) { pointer = public_key_create(s); }
///    const char* Get_Hex_Str() { return public_key_get_key(pointer); }
///    ~PrivateKey() { public_key_destroy(pointer); }
/// private:
///   PrivateKey* pointer;
/// }

#[no_mangle]
pub unsafe extern "C" fn private_key_create(hex: *const c_char) -> *mut WalletPrivateKey
{
    let str = CStr::from_ptr(hex).to_str().unwrap().to_owned();
    let pk = WalletPrivateKey::from_hex(str.as_str()).unwrap();//::from_hex(str);
    Box::into_raw(Box::new(pk))
}

#[no_mangle]
pub unsafe extern "C" fn private_key_destroy(pk: *mut WalletPrivateKey) {
    if !pk.is_null() {
        Box::from_raw(pk);
    }
}

#[no_mangle]
pub unsafe extern "C" fn private_key_get_key(pk: *mut WalletPrivateKey) -> *mut c_char
{
    let mut result = CString::new("").unwrap();
    if !pk.is_null() {
        result = CString::new((*pk).to_hex()).unwrap();
    }
    CString::into_raw(result)
}

/// -------------------------------------------------------------------------------------------- ///

// use tari_core::transaction_protocol::sender::RawTransactionInfo;

// TODO implement this
// Assuming this should look like this?
// pub struct WalletFfi {
//    runtime: tokio::runtime::Runtime,
//    current_wallet: wallet
// }

pub struct IdentityFfi {
    public_key: WalletPublicKey,
    secret_key: WalletPrivateKey,
}

pub struct KeyManagerStateFfi {
    master_seed: WalletPrivateKey,
    branch_seed: String,
    index: c_uint,
}

pub struct KeyManagerSeedWords {
    words: Vec<String>,
}

pub struct NetworkStatusFfi {}

/// Returns a pointer to an initialized Wallet Ffi container. This container needs to be populated with the persistent
/// data before it can be started.
/// The generate_identity() function can provide the public_key, private_key data for you
#[no_mangle]
pub unsafe extern "C" fn create_wallet(
    // Local Node Identity data
    public_key: *const PublicKey,         // Byte[32] - PublicKey
    secret_key: *const PrivateKey,         // Byte[32] - SecretKey
    net_address: *const NetAddress,        // NetAddress
    datastore_path: *const c_char,     // String
    peer_database_name: *const c_char, // String
) -> *mut Wallet
{
    Wallet::new();
    // Each item should be parsed from string to the native datatype to check it is properly formed i.e. a netaddress
    // must be of form "1.2.3.4:5678"
}

/// After the Wallet has been populated with the current state data this call starts it up.
#[no_mangle]
pub unsafe extern "C" fn start_wallet(wallet: *mut Wallet) -> bool {}

// Following methods are to populate the starting state of the wallet from the Clients persistent datastore which MUST
// be done before starting the Wallet

/// Set the Key Manager
#[no_mangle]
pub unsafe extern "C" fn set_key_manager(
    wallet: *mut Wallet,
    master_key: *const c_char,  // Byte[32] - PrivateKey
    branch_seed: *const c_char, // String,
    index: c_uint,
) -> bool
{
}

/// Add an output to the wallet. `spent` is a boolean that indicates if this output is a spent or unspent output.
#[no_mangle]
pub unsafe extern "C" fn add_output(
    wallet: *mut Wallet,
    spent: char,                 // Bool,
    value: c_ulonglong,          // u64
    spending_key: *const c_char, // Byte[32] - PrivateKey,
    feature_flags: c_char,       // OutputFlags,
    maturity: c_ulonglong,       // u64
) -> bool
{
}

/// Initialize a PendingTransactionOutputs struct to be populated
#[no_mangle]
pub unsafe extern "C" fn create_pending_transaction_outputs(
    tx_id: c_ulonglong,       // u64
    timestamp: *const c_char, // NaiveDateTime
) -> *mut PendingTransactionOutputs
{
    Box::into_raw(Box::new(PendingTransactionOutputs {
        tx_id,
        outputs_to_be_spent: Vec::new(),
        outputs_to_be_received: Vec::new(),
        timestamp: NaiveDateTime::parse_from_str("timestamp", "THE FORMAT WE CHOOSE").unwrap_or(NaiveDateTime::now), /* Use the rfc-3339 Format for this. */
    }))
}

/// Append an UnblindedOutput to be spent to the pending transaction outputs object
#[no_mangle]
pub unsafe extern "C" fn add_output_to_spend(
    pending_tx: *mut PendingTransactionOutputs,
    value: c_ulonglong,
    spending_key: *const c_char,
    feature_flags: c_char, // OutputFlags,
    maturity: c_ulonglong, // u64
) -> bool
{
    // append this output to PendingTransactionOutputs.outputs_to_be_spent
}

/// Append an UnblindedOutput to be recieved to the pending transaction outputs object
#[no_mangle]
pub unsafe extern "C" fn add_output_to_received(
    pending_tx: *mut PendingTransactionOutputs,
    value: c_ulonglong,
    spending_key: *const c_char,
    feature_flags: c_char, // OutputFlags,
    maturity: c_ulonglong, // u64
) -> bool
{
    // append this output to PendingTransactionOutputs.outputs_to_be_received
}

/// Add an output to the wallet. `spent` is a boolean that indicates if this output is a spent or unspent output.
#[no_mangle]
pub unsafe extern "C" fn add_pending_transaction_outputs(
    wallet: *mut Wallet,
    pending_tx: *mut PendingTransactionOutputs,
) -> bool
{
    // append this data to the wallet
}

/// Initialize a Transaction struct to be populated
#[no_mangle]
pub unsafe extern "C" fn create_transaction(
    tx_id: c_ulonglong,    // u64
    offset: *const c_char, // Byte[32] - PrivateKey
) -> *mut Transaction
{
}

/// Add a transaction input to a transaction struct
#[no_mangle]
pub unsafe extern "C" fn add_transaction_input(
    transaction: *mut Transaction,
    commitment: *const c_char, // Byte[32] - Commitment
    feature_flags: c_char,     // OutputFlags,
    maturity: c_ulonglong,     // u64
) -> bool
{
    // append input to tx
}

/// Add a transaction output to a transaction struct
#[no_mangle]
pub unsafe extern "C" fn add_transaction_output(
    transaction: *mut Transaction,
    commitment: *const c_char, // Byte[32] - Commitment
    proof: *const c_char,      // Byte[32] - Rangeproof
    feature_flags: c_char,     // OutputFlags,
    maturity: c_ulonglong,     // u64
) -> bool
{
    // append output to tx
}

/// Add a transaction kernel to a transaction struct
#[no_mangle]
pub unsafe extern "C" fn add_transaction_kernel(
    transaction: *mut Transaction,
    features: c_char, // KernelFeatures,
    fee: c_ulonglong, // MicroTari,
    lock_height: u64,
    meta_info: *const c_char,     // Option<Byte[32]> - Option<HashOutput>,
    linked_kernel: *const c_char, // Option<Byte[32]> - Option<HashOutput>,
    excess: *const c_char,        // Byte[32] - Commitment,
    excess_sig: *const c_char,    // Byte[32] - Signature,
) -> bool
{
    // append kernel to tx
}

/// Add an completed transaction to the wallet.
#[no_mangle]
pub unsafe extern "C" fn add_transaction(wallet: *mut Wallet, pending_tx: *mut Transaction) -> bool {}

/// Add a ReceivedTransactionProtocol instance to the wallet
#[no_mangle]
pub unsafe extern "C" fn add_pending_inbound_transaction(
    wallet: *mut Wallet,
    tx_id: c_ulonglong,               // u64,
    public_spend_key: *const c_char,  // Byte[32] - PublicKey,
    partial_signature: *const c_char, // Byte[32] - Signature,
    // TransactionOutput
    commitment: *const c_char, // Byte[32] - Commitment
    proof: *const c_char,      // Byte[32] - Rangeproof
    feature_flags: c_char,     // OutputFlags,
    maturity: c_ulonglong,     // u64
) -> bool
{
    // append this data to the wallet.
    // Assume it is RecipientState::Finalized
    // TODO figure out best way to get this into the Rust struct, the protocol structs are strictly locked down
}

/// Create an initial RawTransactionInfo struct that will be used to build the SenderTransactionProtocol
#[no_mangle]
pub unsafe extern "C" fn create_pending_outbound_transaction(
    num_recipients: c_uint,                // usize,
    amount_to_self: c_ulonglong,           // MicroTari,
    change: c_ulonglong,                   // MicroTari,
    offset: *const c_char,                 // Byte[32] - BlindingFactor,
    offset_blinding_factor: *const c_char, // Byte[32] - BlindingFactor,
    public_excess: *const c_char,          // Byte[32] - PublicKey,
    private_nonce: *const c_char,          // Byte[32] - PrivateKey,
    public_nonce: *const c_char,           // Byte[32] - PublicKey,
    public_nonce_sum: *const c_char,       // Byte[32] - PublicKey,
    // Metadata members
    fee: c_ulonglong,             // MicroTari,
    lock_height: c_ulonglong,     // u64,
    meta_info: *const c_char,     // Option<Byte[32]> - Option<HashOutput>,
    linked_kernel: *const c_char, // Option<Byte[32]> - Option<HashOutput>,
    // RecipientInfo members
    tx_id: c_ulonglong,               // u64,
    output: *const c_char,            // Byte[32] - TransactionOutput,
    public_spend_key: *const c_char,  // Byte[32] - PublicKey,
    partial_signature: *const c_char, // Byte[32] - Signature,
) -> () //*mut RawTransactionInfo, //TODO Figure out the best way to expose this struct for this interface
{
    // create the initial RawTransactionInfo struct that will be used to construct the pending outbound transaction
}

/// Append an id to a pending outbound transaction RawTransactionInfo struct
#[no_mangle]
pub unsafe extern "C" fn add_pending_outbound_id(
    // raw_info: *mut RawTransactionInfo, //TODO RawTransactionInfo is private
    id: c_ulonglong,
) -> bool
{
    // append id
}

/// Append an id to a pending outbound transaction RawTransactionInfo struct
#[no_mangle]
pub unsafe extern "C" fn add_pending_outbound_amount(
    // raw_info: *mut RawTransactionInfo, //TODO RawTransactionInfo is private
    amount: c_ulonglong,
) -> bool
{
    // append amount
}

/// Append an id to a pending outbound transaction RawTransactionInfo struct
#[no_mangle]
pub unsafe extern "C" fn add_pending_outbound_input(
    // raw_info: *mut RawTransactionInfo, //TODO RawTransactionInfo is private
    commitment: *const c_char, // Byte[32] - Commitment
    feature_flags: c_char,     // OutputFlags,
    maturity: c_ulonglong,     // u64
) -> bool
{
    // append input
}

/// Append an id to a pending outbound transaction RawTransactionInfo struct
#[no_mangle]
pub unsafe extern "C" fn add_pending_outbound_output(
    // raw_info: *mut RawTransactionInfo, //TODO RawTransactionInfo is private
    commitment: *const c_char, // Byte[32] - Commitment
    proof: *const c_char,      // Byte[32] - Rangeproof
    feature_flags: c_char,     // OutputFlags,
    maturity: c_ulonglong,     // u64
) -> bool
{
    // append output
}

/// Append an id to a pending outbound transaction RawTransactionInfo struct
#[no_mangle]
pub unsafe extern "C" fn add_pending_outbound_signature(
    // raw_info: *mut RawTransactionInfo, //TODO RawTransactionInfo is private
    signature: *const c_char, // Byte[32] - Signature
) -> bool
{
    // append signature
}

/// Add an completed transaction to the wallet.
#[no_mangle]
pub unsafe extern "C" fn add_pending_outbound_transaction(
    wallet: *mut Wallet,
    // raw_info: *mut RawTransactionInfo, //TODO RawTransactionInfo is private
) -> bool
{
    // Build the SenderTransactionProtocol and append it.
}

// ------------------------------------------------------------------------------------------------
// API Functions
// ------------------------------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn generate_master_seed(wallet: *mut Wallet) -> *mut KeyManagerStateFfi {}
// TODO C Destructuring methods for the KeyManagerStateFfi struct

#[no_mangle]
pub unsafe extern "C" fn get_seed_words(wallet: *mut Wallet) -> *mut KeyManagerSeedWords {}
// TODO C Destructuring methods for the KeyManagerSeedWords struct

#[no_mangle]
pub unsafe extern "C" fn create_seed_words() -> KeyManagerSeedWords {}

#[no_mangle]
pub unsafe extern "C" fn add_seed_word(
    seed_words: *mut KeyManagerSeedWords,
    word: *const c_char, // String
) -> bool
{
}

#[no_mangle]
pub unsafe extern "C" fn generate_key_manager_from_seed_words(
    wallet: *mut Wallet,
    seed_words: *mut KeyManagerSeedWords,
    branch_seed: *const c_char, // String
) -> bool
{
}

#[no_mangle]
pub unsafe extern "C" fn generate_identity(wallet: *mut Wallet) -> *mut IdentityFfi {}
// TODO C Destructuring methods for the IdentityFfi struct

#[no_mangle]
pub unsafe extern "C" fn add_base_node_peer(
    wallet: *mut Wallet,
    public_key: *const c_char,  // Byte[32] - PublicKey
    secret_key: *const c_char,  // Byte[32] - SecretKey
    net_address: *const c_char, // NetAddress
) -> bool
{
}

#[no_mangle]
pub unsafe extern "C" fn get_network_status(wallet: *mut Wallet) -> *mut NetworkStatusFfi {}
// TODO C Destructuring methods for the NetworkStatusFfi struct

#[no_mangle]
pub unsafe extern "C" fn get_balance(wallet: *mut Wallet) -> c_ulonglong {}

// Create and send the first stage of a transaction to the specified wallet for the specified amount and with the
// specified fee.
#[no_mangle]
pub unsafe extern "C" fn send_transaction(
    wallet: *mut Wallet,
    amount: c_ulonglong,       // MicroTari
    fee_per_gram: c_ulonglong, // MicroTari
    lock_height: c_ulonglong,  // u64
    // Destination Node Peer
    public_key: *const c_char,  // Byte[32] - PublicKey
    net_address: *const c_char, // NetAddress
) -> bool
{
    // This function will need to check if the peer already exists and if not create it before sending
    // A callback will be used by LibWallet to send the resultant data back to the client for storage.
}

/// Cancel a pending outbound transaction so that the wallet will not complete and broadcast it if a reply is received
#[no_mangle]
pub unsafe extern "C" fn cancel_transaction(wallet: *mut Wallet, tx_id: c_ulonglong) -> bool {}

// ------------------------------------------------------------------------------------------------
// Callback Functions
// ------------------------------------------------------------------------------------------------
// These functions must be implemented by the FFI client and registered with LibWallet so that
// LibWallet can directly respond to the client when events occur

// Initialize a new PendingTransactionOutputs record
// int create_pending_transaction_outputs(longlong tx_id, char* timestamp) {}

// Append an output to be spent onto an existing PendingTransactionOutputs record
// int add_output_to_be_spent(
//      ulonglong tx_id,
//      ulonglong value,
//      *char spending_key,
//      uchar feature_flags,
//      ulonglong maturity
// ) {}

// Append an output to be received onto an existing PendingTransactionOutputs record
// int add_output_to_be_received(
//      ulonglong tx_id,
//      ulonglong value,
//      *char spending_key,
//      uchar feature_flags,
//      ulonglong maturity,
// ) {}

// This function should result in the outputs that are tied up in a PendingTransactionOutputs collection to be moved to
// spent and unspent respectively
//      int confirm_pending_tx_outputs(longlong tx_id){}

// This function should result in the `outputs to be spent` that are tied up in a PendingTransactionOutputs collection
// to be moved to unspent and the `outputs to be received` should be dropped
//      int cancel_pending_tx_outputs(longlong tx_id){}

// Create a Pending Inbound Transaction
// int add_pending_inbound_transaction(
//    ulonglong tx_id ,
//    *char output,
//    *char public_spend_key,
//    *char partial_signature,
//) {}

// Initialize a new PendingOutboundTransaction record
// int create_pending_outbound_transaction(
//    uint num_recipients,
//    ulonglong amount_to_self,
//    ulonglong change,
//    *char offset,
//    *char offset_blinding_factor,
//    *char public_excess,
//    *char private_nonce,
//    *char public_nonce,
//    *char public_nonce_sum,
//    // Metadata members
//    ulonglong fee,
//    ulonglong lock_height,
//    *char meta_info,
//    *char linked_kernel,
//    // RecipientInfo members
//    ulonglong tx_id,
//    *char output,
//    *char public_spend_key,
//    *char partial_signature
//) {}

// Append an ID to an existing Pending Outbound Transaction record
// int add_pending_outbound_id(longlong tx_id, longlong id) {}

// Append an amount to an existing Pending Outbound Transaction record
// int add_pending_outbound_amount(longlong tx_id, longlong amount) {}

// Append an input to an existing Pending Outbound Transaction record
// int add_pending_outbound_input(longlong tx_id, *char commitment, char features) {}

// Append an output to an existing Pending Outbound Transaction record
// int add_pending_outbound_output(
//      longlong tx_id,
//      *char commitment,
//      *char proof,
//      uchar feature_flags,
//      ulonglong maturity
// ) {}

// Initialize a new Completed Transaction record
// int create_completed_transaction(longlong tx_id, *char offset){}

// Append an input to an existing Completed Transaction record
// int add_pending_transaction_input(longlong tx_id, *char commitment, char features) {}

// Append an output to an existing Completed Transaction record
// int add_pending_transaction_output(
//      longlong tx_id,
//      *char commitment,
//      *char proof,
//      uchar feature_flags,
//      ulonglong maturity
// ) {}

// Append a transaction kernel to an existing Completed Transaction record
// int add_pending_transaction_kernel(
//    longlong tx_id,
//    char features,
//    longlong fee,
//    longlong lock_height,
//    *char meta_info,
//    *char linked_kernel,
//    *char excess,
//    *char excess_sig,
//) {}

// Mark this Pending Inbound Transaction as Confirmed and clean up the DB accordingly
// int confirm_pending_inbound_transaction(longlong tx_id){}
// Mark this Pending Outbound Transaction as Confirmed and clean up the DB accordingly
// int confirm_pending_outbound_transaction(longlong tx_id){}
