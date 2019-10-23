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
use crate::wallet::WalletConfig;
use crate::output_manager_service::handle::OutputManagerResponse::TransactionCancelled;
use tari_core::transaction::{TransactionOutput, TransactionInput, TransactionKernel};
use tari_comms::peer_manager::Peer;

pub type TariWallet = Wallet;
pub type WalletDateTime = NaiveDateTime;

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

/// -------------------------------- Private Key ----------------------------------------------- ///
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
pub type WalletPublicKey = PrivateKey;

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

/// -------------------------------- KeyManagerWords ------------------------------------------- ///
pub struct KeyManagerSeedWords {
    words: Vec<String>,
}

/// Returns a pointer to the sent messages
#[no_mangle]
pub unsafe extern "C" fn keymanager_seed_words_create() -> *mut KeyManagerSeedWords {
    let m =  KeyManagerSeedWords {
        words: Vec::new()
    };

    let boxed = Box::new(m);
    Box::into_raw(boxed)
}

/// Returns a pointer to the KeyManagerSeedWords vector
#[no_mangle]
pub unsafe extern "C" fn keymanager_seed_words_contents(
    mgr: *mut KeyManagerSeedWords,
    i: c_int,
) -> *const c_char
{
    if mgr.is_null() {
        return std::ptr::null_mut();
    }
    let words = &mut (*mgr).words;
    let word= words.get(i as usize).unwrap();
    let m = CString::new(word.as_str()).unwrap();
    CString::into_raw(m)
}

/// Returns the number of KeyManagerSeedWords, zero-indexed
#[no_mangle]
pub unsafe extern "C" fn keymanager_seed_words_add_word(s: *const c_char, mgr: *mut KeyManagerSeedWords) -> bool {
    if mgr.is_null() {
        return false;
    }
    let mut add = CString::new("").unwrap();
    if s.is_null() {
        return false;
    }
    let str = CStr::from_ptr(s).to_str().unwrap().to_owned();
    (*mgr).words.push(str);
    return true
}

/// Returns the number of KeyManagerSeedWords, zero-indexed
#[no_mangle]
pub unsafe extern "C" fn keymanager_seed_words_length(vec: *const KeyManagerSeedWords) -> c_int {
    if vec.is_null() {
        return 0;
    }

    (&*vec).words.len() as c_int
}

#[no_mangle]
pub unsafe extern "C" fn keymanager_seed_words_destroy(obj: *mut KeyManagerSeedWords) {
    // as a rule of thumb, freeing a null pointer is just a noop.
    if obj.is_null() {
        return;
    }

    Box::from_raw(obj);
}

/// -------------------------------------------------------------------------------------------- ///

//pub struct NetworkStatusFfi {}
/// -------------------------------- Comms Config ---------------------------------------------- ///


/// -------------------------------------------------------------------------------------------- ///
/// -------------------------------- OutputManager Config -------------------------------------- ///
/// TODO

/// -------------------------------------------------------------------------------------------- ///


/// -------------------------------- Wallet Config --------------------------------------------- ///
/// TODO
/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- KeyManagerState Config ------------------------------------ ///
pub struct KeyManagerState {
    master_seed: WalletPrivateKey,
    branch_seed: String,
    index: c_uint,
}

pub unsafe extern "C" fn KeyManagerState_Create ( master_key: *const WalletPrivateKey,
                                                  branch_seed: *mut c_char,
                                                  index: c_uint) -> *mut KeyManagerState
{
    let m = KeyManagerState {
        master_seed : (*master_key).to_owned(),
        branch_seed : CString::from_raw(branch_seed).to_str().unwrap().to_owned(),
        index: index
    };
    Box::into_raw(Box::new(m))
}

pub unsafe extern "C" fn KeyManagerState_Destroy (state: *mut KeyManagerState )
{
    if !state.is_null() {
        Box::from_raw(state);
    }
}
/// -------------------------------------------------------------------------------------------- ///

/// -----------------------------------------Unblinded Output------------------------------------ ///
pub type WalletUnblindedOutput = UnblindedOutput;
/// TODO
/// -------------------------------------------------------------------------------------------- ///

///----- PendingTransactionOutputs-------------------------------------------------------------- ///
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
        timestamp: NaiveDateTime::parse_from_str("timestamp", "THE FORMAT WE CHOOSE").unwrap(), /* Use the rfc-3339 Format for this. */
    }))
}

#[no_mangle]
pub unsafe extern "C" fn destroy_pending_transaction_outputs(pto: *mut PendingTransactionOutputs)
{
    if !pto.is_null() {
        Box::from_raw(pto);
    }
}
/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- Compound Inputs, Outputs, Kernels ------------------------- ///
/// Initialize a Transaction struct to be populated
pub struct TransactionInputs(Vec<TransactionInput>);
pub struct TransactionOutputs(Vec<TransactionOutput>);
pub struct TransactionKernels(Vec<TransactionKernel>);

/// Add a transaction input to a transaction struct
#[no_mangle]
pub unsafe extern "C" fn add_transaction_input(
    inputs: *mut TransactionInputs,
    transaction: *mut TransactionInput
) -> bool
{
    if inputs.is_null() {
        return false;
    }

    if transaction.is_null() {
        return false;
    }

    (*inputs).0.push((*transaction).clone());
    return true;
}

/// Add a transaction output to a transaction struct
#[no_mangle]
pub unsafe extern "C" fn add_transaction_output(
    outputs: *mut TransactionOutputs,
    transaction: *mut TransactionOutput
) -> bool
{
    if outputs.is_null() {
        return false;
    }

    if transaction.is_null() {
        return false;
    }

    (*outputs).0.push((*transaction).clone());
    return true;
}

/// Add a transaction kernel to a transaction struct
#[no_mangle]
pub unsafe extern "C" fn add_transaction_kernel(
    kernels: *mut TransactionKernels,
    kernel: *mut TransactionKernel,
) -> bool
{
    if kernels.is_null() {
        return false;
    }

    if kernel.is_null() {
        return false;
    }

    (*kernels).0.push((*kernel).clone());
    return true;
}

/// -------------------------------------------------------------------------------------------- ///

/// -------------------------------- Wallet ---------------------------------------------------- ///
pub type WalletMasterConfig = WalletConfig;

pub unsafe extern "C" fn create_wallet(
    // Local Node Identity data
    config: *const WalletMasterConfig,
) -> *mut Wallet
{
    // TODO do null check for config, runtime
    let runtime = Runtime::new();
    let mut w = Wallet::new((*config).clone(), runtime.unwrap());
    Box::into_raw(Box::new(w.unwrap()))
}

#[no_mangle]
pub unsafe extern "C" fn start_wallet(wallet: *mut Wallet) -> bool
{
    // (*wallet).start() ? true : false; implement start() on wallet
    // i.e return (*wallet).start()
    true
}

/// Set the Key Manager
#[no_mangle]
pub unsafe extern "C" fn set_key_manager(
    wallet: *mut Wallet,
    state: *mut KeyManagerState,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if state.is_null() {
        return false;
    }

    // (*wallet).key_manager.state = (*state) ? true : false; implement SetState() on Wallet
    // i.e return (*wallet).SetState((*state));
    return true;
}

/// Add an output to the wallet. `spent` is a boolean that indicates if this output is a spent or unspent output.
#[no_mangle]
pub unsafe extern "C" fn add_output(
    wallet: *mut Wallet,
    output: *mut WalletUnblindedOutput,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if output.is_null() {
        return false;
    }

    (*wallet).output_manager_service.add_output((*output).clone()); // ? true : false; implement AddOutput(O: UnblindedOutput) -> bool on Wallet
    // i.e return (*wallet).addOutput((*output));
    return true;
}

/// Append an UnblindedOutput to be spent to the pending transaction outputs object
#[no_mangle]
pub unsafe extern "C" fn add_output_to_spend(
    wallet: *mut TariWallet,
    output: *mut WalletUnblindedOutput,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if output.is_null() {
        return false;
    }

    // (*wallet).pendingtransactionoutputs.addSpendoutput((*output)) ? true : false;
    return true;
}

/// Append an UnblindedOutput to be received to the pending transaction outputs object
#[no_mangle]
pub unsafe extern "C" fn add_output_to_received(
    wallet: *mut TariWallet,
    output: *mut WalletUnblindedOutput,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if output.is_null() {
        return false;
    }

    // (*wallet).pendingtransactionoutputs.addReceivedoutput((*output)) ? true : false;
    return true;
}

/// Add an output to the wallet. `spent` is a boolean that indicates if this output is a spent or unspent output.
#[no_mangle]
pub unsafe extern "C" fn add_pending_transaction_outputs(
    wallet: *mut Wallet,
    output: *mut PendingTransactionOutputs,
    spent: bool
) -> bool
{

    if wallet.is_null() {
        return false;
    }

    if output.is_null() {
        return false;
    }

    match spent
        {
            true => {}//(*wallet).pendingtransactionoutputs.addSpentOutput((*output)) ? true : false;
            false => {}//(*wallet).pendingtransactionoutputs.addReceivedOutput((*output)) ? true : false;
        }
    return true;
}

/// TODO Methods to construct, free above 3 types

#[no_mangle]
pub unsafe extern "C" fn create_transaction(
    inputs: *mut TransactionInputs,
    outputs: *mut TransactionOutputs,
    kernels: *mut TransactionKernels,
    offset: *const PrivateKey,
) -> *mut Transaction
{
    ///TODO null check
    let t = Transaction::new((*inputs).0.clone(),(*outputs).0.clone(),(*kernels).0.clone(),(*offset).clone());
    Box::into_raw(Box::new(t))
}

/// Add an completed transaction to the wallet.
/// ??????????????????????????????????????????
#[no_mangle]
pub unsafe extern "C" fn add_transaction(wallet: *mut Wallet, pending_tx: *mut Transaction, inbound: bool) -> bool {
    return true;
}

/// Add a ReceivedTransactionProtocol instance to the wallet
#[no_mangle]
pub unsafe extern "C" fn add_pending_inbound_transaction(
    wallet: *mut Wallet,
    transaction: *mut Transaction,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if transaction.is_null() {
        return false;
    }

    //(*wallet).pendingtransactionoutputs.addinboundtransaction((*transaction)) ? true : false;

    return true;
    // append this data to the wallet.
    // Assume it is RecipientState::Finalized
    // TODO figure out best way to get this into the Rust struct, the protocol structs are strictly locked down
}

/// Add a ReceivedTransactionProtocol instance to the wallet
#[no_mangle]
pub unsafe extern "C" fn add_pending_outbound_transaction(
    wallet: *mut Wallet,
    transaction: *mut Transaction,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if transaction.is_null() {
        return false;
    }

    //(*wallet).pendingtransactionoutputs.addoutboundtransaction((*transaction)) ? true : false;

    return true;
    // append this data to the wallet.
    // Assume it is RecipientState::Finalized
    // TODO figure out best way to get this into the Rust struct, the protocol structs are strictly locked down
}

/// Create an initial RawTransactionInfo struct that will be used to build the SenderTransactionProtocol
//#[no_mangle]
//pub unsafe extern "C" fn create_pending_outbound_transaction(
//    num_recipients: c_uint,                // usize,
//    amount_to_self: c_ulonglong,           // MicroTari,
//    change: c_ulonglong,                   // MicroTari,
//    offset: *const c_char,                 // Byte[32] - BlindingFactor,
//    offset_blinding_factor: *const c_char, // Byte[32] - BlindingFactor,
//    public_excess: *const c_char,          // Byte[32] - PublicKey,
//    private_nonce: *const c_char,          // Byte[32] - PrivateKey,
//    public_nonce: *const c_char,           // Byte[32] - PublicKey,
//    public_nonce_sum: *const c_char,       // Byte[32] - PublicKey,
    // Metadata members
//    fee: c_ulonglong,             // MicroTari,
//    lock_height: c_ulonglong,     // u64,
//    meta_info: *const c_char,     // Option<Byte[32]> - Option<HashOutput>,
//    linked_kernel: *const c_char, // Option<Byte[32]> - Option<HashOutput>,
    // RecipientInfo members
//    tx_id: c_ulonglong,               // u64,
//    output: *const c_char,            // Byte[32] - TransactionOutput,
//    public_spend_key: *const c_char,  // Byte[32] - PublicKey,
// partial_signature: *const c_char, // Byte[32] - Signature,
//) -> () //*mut RawTransactionInfo, //TODO Figure out the best way to expose this struct for this interface
//{

//}

/// ------------------------------------------------------------------------------------------- ///


// ------------------------------------------------------------------------------------------------
// API Functions
// ------------------------------------------------------------------------------------------------

//#[no_mangle]
//pub unsafe extern "C" fn generate_master_seed(wallet: *mut Wallet) -> *mut KeyManagerStateFfi {}
//TODO C Destructuring methods for the KeyManagerStateFfi struct

//#[no_mangle]
//pub unsafe extern "C" fn get_seed_words(wallet: *mut Wallet) -> *mut KeyManagerSeedWords {}
// TODO C Destructuring methods for the KeyManagerSeedWords struct

//#[no_mangle]
//pub unsafe extern "C" fn generate_key_manager_from_seed_words(
//wallet: *mut Wallet,
//    seed_words: *mut KeyManagerSeedWords,
//    branch_seed: *const c_char, // String
//) -> bool
//{
//}

//#[no_mangle]
//pub unsafe extern "C" fn generate_identity(wallet: *mut Wallet) -> *mut IdentityFfi {}
// TODO C Destructuring methods for the IdentityFfi struct

#[no_mangle]
pub unsafe extern "C" fn add_base_node_peer(
    wallet: *mut Wallet,
    peer: *mut Peer,
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if peer.is_null() {
        return false;
    }

    // (*wallet).addPeer((*peer));
    return true;
}

//#[no_mangle]
//pub unsafe extern "C" fn get_network_status(wallet: *mut Wallet) -> *mut NetworkStatusFfi {}
// TODO C Destructuring methods for the NetworkStatusFfi struct

#[no_mangle]
pub unsafe extern "C" fn get_balance(wallet: *mut Wallet) -> c_ulonglong {
    //(*wallet).getBalance();
    return 0;
}

// Create and send the first stage of a transaction to the specified wallet for the specified amount and with the
// specified fee.
#[no_mangle]
pub unsafe extern "C" fn send_transaction(
    wallet: *mut Wallet,
    peer: *mut Peer,
    transaction: *mut Transaction
) -> bool
{
    if wallet.is_null() {
        return false;
    }

    if transaction.is_null() {
        return false;
    }

    if peer.is_null() {
        return false;
    }
    //(*wallet).sendTransaction((*transaction)) ? true : false
    return true;
}

/// Cancel a pending outbound transaction so that the wallet will not complete and broadcast it if a reply is received
#[no_mangle]
pub unsafe extern "C" fn cancel_transaction(wallet: *mut Wallet, tr: *mut Transaction) -> bool {
        if wallet.is_null() {
            return false;
        }

        if tr.is_null() {
            return false;
        }

        //(*wallet).cancelTransaction ((*tr)) ? true : false
        return true;
}

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
