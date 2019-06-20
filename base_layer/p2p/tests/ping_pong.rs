//  Copyright 2019 The Tari Project
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//  disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//  following disclaimer in the documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//  products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// NOTE: This test uses ports 11111 and 11112

use p2p::{
    ping_pong::PingPongService,
    services::{ServiceExecutor, ServiceRegistry},
    tari_message::NetMessage,
};
use rand::rngs::OsRng;
use tari_comms::{
    builder::{CommsRoutes, CommsServices},
    connection::NetAddress,
    control_service::ControlServiceConfig,
    peer_manager::NodeIdentity,
    types::CommsPublicKey,
    CommsBuilder,
};
use p2p::tari_message::TariMessageType;
use std::sync::Arc;
use tari_comms::types::CommsDataStore;
use tari_comms::peer_manager::Peer;
use tari_storage::lmdb::LMDBBuilder;
use crate::utils::random_temp_dir;
use tari_storage::keyvalue_store::DataStore;

fn new_node_identity(control_service_address: NetAddress) -> NodeIdentity<CommsPublicKey> {
    NodeIdentity::random(&mut OsRng::new().unwrap(), control_service_address).unwrap()
}

fn create_peer_storage(name: &str, peers: Vec<Peer<CommsPublicKey>>) -> CommsDataStore {
    let mut dir = random_temp_dir();
    let mut store = LMDBBuilder::new().set_path(dir.into()).build().unwrap();
    store.put_raw()

    store
}

fn setup_services(node_identity: NodeIdentity<CommsPublicKey>, peer_storage: CommsDataStore) -> ServiceExecutor {
    let services = ServiceRegistry::new().register(PingPongService::new());

    let comms = CommsBuilder::new()
        .with_routes(services.build_comms_routes())
        .with_node_identity(node_identity)
        .with_peer_storage(peer_storage)
        .configure_control_service(ControlServiceConfig{
            socks_proxy_address: None,
            listener_address: node_identity.control_service_address.clone(),
            accept_message_type: TariMessageType::new(NetMessage::Accept),
        })
        .build()
        .unwrap()
        .start()
        .unwrap();

    ServiceExecutor::execute(Arc::new(comms), services)
}

#[test]
#[allow(non_snake_case)]
fn end_to_end() {
    let node_A_identity = new_node_identity("127.0.0.1:11111".parse().unwrap());
    let node_B_identity = new_node_identity("127.0.0.1:11112".parse().unwrap());

    let node_A_services = setup_services(node_A_identity, create_peer_storage("peer_A", vec![node_B_identity.clone().into()]));
    let node_B_services = setup_services(node_B_identity, create_peer_storage("peer_B", vec![node_A_identity.clone().into()]));


}
