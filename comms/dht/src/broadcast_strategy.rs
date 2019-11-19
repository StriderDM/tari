// Copyright 2019, The Tari Project
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

use std::{fmt, fmt::Formatter};
use tari_comms::{peer_manager::node_id::NodeId, types::CommsPublicKey};

#[derive(Debug, Clone)]
pub struct BroadcastClosestRequest {
    pub n: usize,
    pub node_id: NodeId,
    pub excluded_peers: Vec<CommsPublicKey>,
}

#[derive(Debug, Clone)]
pub enum BroadcastStrategy {
    /// Send to a particular peer matching the given node ID
    DirectNodeId(NodeId),
    /// Send to a particular peer matching the given Public Key
    DirectPublicKey(CommsPublicKey),
    /// Send to all known Communication Node peers
    Flood,
    /// Send to a random set of peers of size n that are Communication Nodes
    Random(usize),
    /// Send to all n nearest Communication Nodes according to the given BroadcastClosestRequest
    Closest(Box<BroadcastClosestRequest>),
    /// A convenient strategy which behaves the same as the `Closest` strategy with the `NodeId` set
    /// to this node and a pre-configured number of neighbours. This strategy excludes the given public keys.
    Neighbours(Vec<CommsPublicKey>),
}

impl fmt::Display for BroadcastStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        use BroadcastStrategy::*;
        match self {
            DirectPublicKey(pk) => write!(f, "DirectPublicKey({})", pk),
            DirectNodeId(node_id) => write!(f, "DirectNodeId({})", node_id),
            Flood => write!(f, "Flood"),
            Closest(request) => write!(f, "Closest({})", request.n),
            Random(n) => write!(f, "Random({})", n),
            Neighbours(excluded) => write!(f, "Neighbours({} excluded)", excluded.len()),
        }
    }
}

impl BroadcastStrategy {
    pub fn is_direct(&self) -> bool {
        use BroadcastStrategy::*;
        match self {
            DirectNodeId(_) | DirectPublicKey(_) => true,
            _ => false,
        }
    }

    pub fn direct_node_id(&self) -> Option<&NodeId> {
        use BroadcastStrategy::*;
        match self {
            DirectNodeId(node_id) => Some(node_id),
            _ => None,
        }
    }

    pub fn direct_public_key(&self) -> Option<&CommsPublicKey> {
        use BroadcastStrategy::*;
        match self {
            DirectPublicKey(pk) => Some(pk),
            _ => None,
        }
    }

    pub fn take_direct_public_key(self) -> Option<CommsPublicKey> {
        use BroadcastStrategy::*;
        match self {
            DirectPublicKey(pk) => Some(pk),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn is_direct() {
        assert!(BroadcastStrategy::DirectPublicKey(CommsPublicKey::default()).is_direct());
        assert!(BroadcastStrategy::DirectNodeId(NodeId::default()).is_direct());
        assert_eq!(BroadcastStrategy::Neighbours(Default::default()).is_direct(), false);
        assert_eq!(BroadcastStrategy::Flood.is_direct(), false);
        assert_eq!(
            BroadcastStrategy::Closest(Box::new(BroadcastClosestRequest {
                node_id: NodeId::default(),
                n: 0,
                excluded_peers: Default::default()
            }))
            .is_direct(),
            false
        );
        assert_eq!(BroadcastStrategy::Random(0).is_direct(), false);
    }

    #[test]
    fn direct_public_key() {
        assert!(BroadcastStrategy::DirectPublicKey(CommsPublicKey::default())
            .direct_public_key()
            .is_some());
        assert!(BroadcastStrategy::DirectNodeId(NodeId::default())
            .direct_public_key()
            .is_none());
        assert!(BroadcastStrategy::Neighbours(Default::default())
            .direct_public_key()
            .is_none());
        assert!(BroadcastStrategy::Flood.direct_public_key().is_none());
        assert!(BroadcastStrategy::Closest(Box::new(BroadcastClosestRequest {
            node_id: NodeId::default(),
            n: 0,
            excluded_peers: Default::default()
        }))
        .direct_public_key()
        .is_none(),);
        assert!(BroadcastStrategy::Random(0).direct_public_key().is_none(), false);
    }

    #[test]
    fn direct_node_id() {
        assert!(BroadcastStrategy::DirectPublicKey(CommsPublicKey::default())
            .direct_node_id()
            .is_none());
        assert!(BroadcastStrategy::DirectNodeId(NodeId::default())
            .direct_node_id()
            .is_some());
        assert!(BroadcastStrategy::Neighbours(Default::default())
            .direct_node_id()
            .is_none());
        assert!(BroadcastStrategy::Flood.direct_node_id().is_none());
        assert!(BroadcastStrategy::Closest(Box::new(BroadcastClosestRequest {
            node_id: NodeId::default(),
            n: 0,
            excluded_peers: Default::default()
        }))
        .direct_node_id()
        .is_none(),);
        assert!(BroadcastStrategy::Random(0).direct_node_id().is_none(), false);
    }
}
