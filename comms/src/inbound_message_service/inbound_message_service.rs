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
use crate::{
    inbound_message_service::{error::InboundMessagePipelineError, MessageCache, MessageCacheConfig},
    message::{Frame, FrameSet, InboundMessage, MessageData},
    peer_manager::{NodeId, Peer, PeerManager},
};
use futures::{channel::mpsc, FutureExt, Sink, SinkExt, Stream, StreamExt};
use log::*;
use std::{convert::TryFrom, sync::Arc};
use tari_shutdown::ShutdownSignal;

const LOG_TARGET: &str = "comms::inbound_message_service";

pub type InboundMessageService<TSink> = InnerInboundMessageService<mpsc::Receiver<FrameSet>, TSink>;

/// The InboundMessageService contains the logic for processing a raw MessageEnvelope received via a PeerConnection and
/// routing it via one of the InboundMessageRoutes. This pipeline contains the logic for the various validations and
/// check done to decide whether this message should be passed further along the pipeline and, be sent to
/// the given message_sink.
pub struct InnerInboundMessageService<TStream, TSink> {
    raw_message_stream: Option<TStream>,
    message_cache: MessageCache<Frame>,
    message_sink: TSink,
    peer_manager: Arc<PeerManager>,
    shutdown_signal: Option<ShutdownSignal>,
}

impl<TStream, TSink> InnerInboundMessageService<TStream, TSink>
where
    TStream: Stream<Item = FrameSet> + Unpin,
    TSink: Sink<InboundMessage> + Unpin,
    TSink::Error: Into<InboundMessagePipelineError>,
{
    pub fn new(
        raw_message_stream: TStream,
        message_sink: TSink,
        peer_manager: Arc<PeerManager>,
        shutdown_signal: ShutdownSignal,
    ) -> Self
    {
        let message_cache = MessageCache::new(MessageCacheConfig::default());
        Self {
            raw_message_stream: Some(raw_message_stream),
            message_sink,
            message_cache,
            peer_manager,
            shutdown_signal: Some(shutdown_signal),
        }
    }

    /// Run the Inbound Message Service on the set `message_sink_receiver` processing each message in that stream. If
    /// an error occurs while processing a message it is logged and the service will move onto the next message. Most
    /// errors represent a reason why a message didn't make it through the pipeline.
    pub async fn run(mut self) -> () {
        let mut shutdown_signal = self
            .shutdown_signal
            .take()
            .expect("InboundMessageService initialized without shutdown_rx")
            .fuse();

        let mut raw_message_stream = self
            .raw_message_stream
            .take()
            .expect("InboundMessageService initialized without raw_message_stream")
            .fuse();

        info!(target: LOG_TARGET, "Inbound Message Pipeline started");
        loop {
            futures::select! {
                frames = raw_message_stream.select_next_some() => {
                    if let Err(e) = self.process_message(frames).await {
                        info!(target: LOG_TARGET, "Inbound Message Pipeline Error: {:?}", e);
                    }
                },

                _ = shutdown_signal => {
                    info!(target: LOG_TARGET, "Inbound message service shutting down because it received the shutdown signal");
                    break;
                }
            }
        }
    }

    /// Process a single received message from its raw serialized form i.e. a FrameSet
    pub async fn process_message(&mut self, frame_set: FrameSet) -> Result<(), InboundMessagePipelineError> {
        let message_data =
            MessageData::try_from(frame_set).map_err(|_| InboundMessagePipelineError::DeserializationError)?;

        let message_envelope_header = message_data
            .message_envelope
            .deserialize_header()
            .map_err(|_| InboundMessagePipelineError::DeserializationError)?;

        if !message_envelope_header.verify_signature(message_data.message_envelope.body_frame())? {
            return Err(InboundMessagePipelineError::InvalidMessageSignature);
        }

        self.message_cache_check(&message_envelope_header.message_signature)?;

        let peer = self.find_known_peer(&message_data.source_node_id)?;

        // Message is deduped and authenticated

        let inbound_message = InboundMessage::new(
            peer,
            message_envelope_header,
            message_data.message_envelope.version(),
            message_data.message_envelope.into_body_frame(),
        );

        self.message_sink.send(inbound_message).await.map_err(Into::into)?;

        Ok(())
    }

    /// Utility Functions that require the Pipeline context resources
    /// Check whether this message body has been received before (within the cache TTL period). If it has then reject
    /// the message, else add it to the cache.
    fn message_cache_check(&mut self, signature: &Vec<u8>) -> Result<(), InboundMessagePipelineError> {
        if !self.message_cache.contains(signature) {
            if let Err(_e) = self.message_cache.insert(signature.clone()) {
                error!(
                    target: LOG_TARGET,
                    "Duplicate message found in Message Cache AFTER checking the cache for the message"
                );
                return Err(InboundMessagePipelineError::DuplicateMessageDiscarded);
            }
            return Ok(());
        } else {
            return Err(InboundMessagePipelineError::DuplicateMessageDiscarded);
        }
    }

    /// Check whether the the source of the message is known to our Peer Manager, if it is return the peer but otherwise
    /// we discard the message as it should be in our Peer Manager
    fn find_known_peer(&self, source_node_id: &NodeId) -> Result<Peer, InboundMessagePipelineError> {
        match self.peer_manager.find_with_node_id(&source_node_id).ok() {
            Some(peer) => Ok(peer),
            None => {
                warn!(
                    target: LOG_TARGET,
                    "Received unknown node id from peer connection. Discarding message from NodeId={:?}",
                    source_node_id
                );
                Err(InboundMessagePipelineError::CannotFindSourcePeer)
            },
        }
    }
}
