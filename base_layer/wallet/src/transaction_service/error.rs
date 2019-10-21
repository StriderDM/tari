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

use crate::output_manager_service::error::OutputManagerError;
use derive_error::Error;
use tari_comms_dht::outbound::DhtOutboundError;
use tari_core::transaction_protocol::TransactionProtocolError;
use tari_service_framework::reply_channel::TransportChannelError;

#[derive(Debug, Error)]
pub enum TransactionServiceError {
    // Transaction protocol is not in the correct state for this operation
    InvalidStateError,
    // Transaction Protocol Error
    TransactionProtocolError(TransactionProtocolError),
    // The message being process is not recognized by the Transaction Manager
    InvalidMessageTypeError,
    // A message for a specific tx_id has been repeated
    RepeatedMessageError,
    // A recipient reply was received for a non-existent tx_id
    TransactionDoesNotExistError,
    /// The Outbound Message Service is not initialized
    OutboundMessageServiceNotInitialized,
    /// Received an unexpected API response
    UnexpectedApiResponse,
    /// Failed to send from API
    ApiSendFailed,
    /// Failed to receive in API from service
    ApiReceiveFailed,
    /// An error has occurred reading or writing the event subscriber stream
    EventStreamError,
    OutboundError(DhtOutboundError),
    OutputManagerError(OutputManagerError),
    TransportChannelError(TransportChannelError),
}
