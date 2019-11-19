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

use crate::support::factories::{self, TestFactory};
use futures::channel::mpsc::{channel, Sender};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tari_comms::{
    connection::{types::Direction, Connection, CurvePublicKey, ZmqContext},
    connection_manager::ConnectionManager,
    control_service::{messages::RequestConnectionOutcome, ControlService, ControlServiceClient, ControlServiceConfig},
    message::FrameSet,
    peer_manager::{NodeId, NodeIdentity, Peer, PeerFeatures, PeerFlags, PeerManager},
};
use tari_storage::{
    lmdb_store::{LMDBBuilder, LMDBDatabase, LMDBError, LMDBStore},
    LMDBWrapper,
};
use tari_utilities::{thread_join::ThreadJoinWithTimeout, ByteArray};

fn make_peer_manager(peers: Vec<Peer>, database: LMDBDatabase) -> Arc<PeerManager> {
    Arc::new(
        factories::peer_manager::create()
            .with_peers(peers)
            .with_database(LMDBWrapper::new(Arc::new(database)))
            .build()
            .unwrap(),
    )
}
fn get_path(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/data");
    path.push(name);
    path.to_str().unwrap().to_string()
}

// Initialize the datastore. Note: every test should have unique database name
fn init_datastore(name: &str) -> Result<LMDBStore, LMDBError> {
    let path = get_path(name);
    let _ = std::fs::create_dir(&path).unwrap_or_default();
    LMDBBuilder::new()
        .set_path(&path)
        .set_environment_size(10)
        .set_max_number_of_databases(2)
        .add_database(name, lmdb_zero::db::CREATE)
        .build()
}

fn clean_up_datastore(name: &str) {
    std::fs::remove_dir_all(get_path(name)).unwrap();
}

fn setup(
    database_name: &str,
    message_sink_sender: Sender<FrameSet>,
) -> (ZmqContext, Arc<NodeIdentity>, Arc<PeerManager>, Arc<ConnectionManager>)
{
    let node_identity = factories::node_identity::create().build().map(Arc::new).unwrap();
    let context = ZmqContext::new();
    let datastore = init_datastore(database_name).unwrap();
    let database = datastore.get_handle(database_name).unwrap();
    let peer_manager = make_peer_manager(vec![], database);
    let connection_manager = factories::connection_manager::create()
        .with_context(context.clone())
        .with_peer_manager(Arc::clone(&peer_manager))
        .with_message_sink_sender(message_sink_sender)
        .build()
        .map(Arc::new)
        .unwrap();

    (context, node_identity, peer_manager, connection_manager)
}

#[test]
fn request_connection() {
    let database_name = "control_service_request_connection";

    let (message_sink_tx, _message_sink_rx) = channel(10);

    let (context, node_identity_a, peer_manager, connection_manager) = setup(database_name, message_sink_tx);

    // Setup the destination peer's control service
    let listener_address = factories::net_address::create().build().unwrap();
    let service_handle = ControlService::new(context.clone(), Arc::clone(&node_identity_a), ControlServiceConfig {
        listener_address: listener_address.clone(),
        socks_proxy_address: None,
        requested_connection_timeout: Duration::from_millis(2000),
    })
    .serve(connection_manager)
    .unwrap();

    // Setup the requesting peer
    let node_identity_b = factories::node_identity::create()
        .with_peer_features(PeerFeatures::COMMUNICATION_NODE)
        .build()
        .map(Arc::new)
        .unwrap();
    // --- Client connection for the destination peer's control service
    let client_conn = Connection::new(&context, Direction::Outbound)
        .establish(&listener_address)
        .unwrap();
    let client = ControlServiceClient::new(
        Arc::clone(&node_identity_b),
        node_identity_a.public_key().clone(),
        client_conn,
    );

    // --- Request a connection to the peer connection
    client
        .send_request_connection(
            node_identity_b.control_service_address(),
            NodeId::from_key(node_identity_b.public_key()).unwrap(),
            node_identity_b.features().clone(),
        )
        .unwrap();
    let outcome = client
        .receive_message::<RequestConnectionOutcome>(Duration::from_millis(3000))
        .unwrap()
        .unwrap();

    let peer = peer_manager.find_by_public_key(node_identity_b.public_key()).unwrap();
    assert_eq!(&peer.public_key, node_identity_b.public_key());
    assert_eq!(&peer.node_id, node_identity_b.node_id());
    assert_eq!(peer.addresses[0], node_identity_b.control_service_address().into());
    assert_eq!(peer.flags, PeerFlags::empty());
    assert_eq!(peer.features, PeerFeatures::COMMUNICATION_NODE);

    assert_eq!(outcome.accepted, true);
    // --- Setup outbound peer connection to the requested address
    let (message_sink_tx2, _message_sink_rx2) = channel(10);
    let (peer_conn, peer_conn_handle) = factories::peer_connection::create()
        .with_peer_connection_context_factory(
            factories::peer_connection_context::create()
                .with_context(&context)
                .with_direction(Direction::Outbound)
                .with_address(outcome.address.parse().unwrap())
                .with_message_sink_channel(message_sink_tx2)
                .with_server_public_key(CurvePublicKey::from_bytes(&outcome.curve_public_key).unwrap()),
        )
        .build()
        .unwrap();

    peer_conn
        .wait_connected_or_failure(&Duration::from_millis(3000))
        .unwrap();

    peer_conn.shutdown().unwrap();
    peer_conn_handle.timeout_join(Duration::from_millis(3000)).unwrap();

    service_handle.shutdown().unwrap();
    service_handle.timeout_join(Duration::from_millis(3000)).unwrap();

    clean_up_datastore(database_name);
}

#[test]
fn ping_pong() {
    let database_name = "control_service_ping_pong";
    let (message_sink_tx, _message_sink_rx) = channel(10);
    let (context, node_identity, _, connection_manager) = setup(database_name, message_sink_tx);

    let listener_address = factories::net_address::create().build().unwrap();
    let service = ControlService::new(context.clone(), Arc::clone(&node_identity), ControlServiceConfig {
        listener_address: listener_address.clone(),
        socks_proxy_address: None,
        requested_connection_timeout: Duration::from_millis(2000),
    })
    .serve(connection_manager)
    .unwrap();

    let client_conn = Connection::new(&context, Direction::Outbound)
        .establish(&listener_address)
        .unwrap();
    let client = ControlServiceClient::new(
        Arc::clone(&node_identity),
        node_identity.public_key().clone(),
        client_conn,
    );

    client.ping_pong(Duration::from_millis(2000)).unwrap().unwrap();

    service.shutdown().unwrap();
    service.timeout_join(Duration::from_millis(3000)).unwrap();

    clean_up_datastore(database_name);
}
