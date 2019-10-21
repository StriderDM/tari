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
//
use crate::{
    base_node::{
        states::{error::BaseNodeError, StateEvent},
        BaseNodeStateMachine,
    },
    chain_storage::BlockchainBackend,
};
use log::*;

const LOG_TARGET: &str = "base_node::starting_state";

// The data structure handling Base Node Startup
pub struct Starting;

impl Starting {
    /// Apply the configuration settings for this node.
    fn apply_config(&mut self) -> Result<(), BaseNodeError> {
        // TODO apply configuration
        Ok(())
    }

    pub async fn next_event<B: BlockchainBackend>(&mut self, _shared: &BaseNodeStateMachine<B>) -> StateEvent {
        info!(target: LOG_TARGET, "Configuring node.");
        if let Err(err) = self.apply_config() {
            return err.as_fatal("There was an error with the base node configuration.");
        }
        info!(target: LOG_TARGET, "Node configuration complete.");
        StateEvent::Initialized
    }
}
