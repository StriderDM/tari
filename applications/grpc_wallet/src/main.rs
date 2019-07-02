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

use std::{collections::HashMap, sync::Arc, time::Duration};
use tari_comms::{
    connection::NetAddress,
    control_service::ControlServiceConfig,
    types::{CommsPublicKey, CommsSecretKey},
};
use tari_crypto::keys::{PublicKey, SecretKey};
use tari_grpc_wallet::grpc_server::{WalletServer, WalletServerConfig};
use tari_p2p::{
    initialization::CommsConfig,
    tari_message::{NetMessage, TariMessageType},
};
use tari_utilities::message_format::MessageFormat;
use tari_wallet::{wallet::WalletConfig, Wallet};

/// Entry point into the gRPC server binary
/// TODO Read finalized Config file and merge with defaults
/// TODO Read Command Line switches and merge with config
pub fn main() {
    let _ = simple_logger::init_with_level(log::Level::Info);

    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("grpc_wallet_sample_config"))
        .unwrap();
    let settings: HashMap<String, String> = settings.try_into().unwrap();

    let listener_address1: NetAddress = format!("127.0.0.1:{}", settings["local_comms_port"]).parse().unwrap();
    let secret_key1 = CommsSecretKey::from_base64(settings["local_node_comms_secret_key"].as_str()).unwrap();
    let public_key1 = CommsPublicKey::from_secret_key(&secret_key1);
    let config = WalletConfig {
        comms: CommsConfig {
            control_service: ControlServiceConfig {
                listener_address: listener_address1.clone(),
                socks_proxy_address: None,
                accept_message_type: TariMessageType::new(NetMessage::Accept),
                requested_outbound_connection_timeout: Duration::from_millis(5000),
            },
            socks_proxy_address: None,
            host: "127.0.0.1".parse().unwrap(),
            public_key: public_key1.clone(),
            secret_key: secret_key1,
            datastore_path: "./".to_string(),
            peer_database_name: "grpc_wallet_peers".to_string(),
        },
        public_key: public_key1.clone(),
    };

    let wallet = Wallet::new(config).unwrap();
    let wallet_config = WalletServerConfig {
        port: settings["local_grpc_port"].parse::<u32>().unwrap(),
    };
    let wallet_server = WalletServer::new(Some(wallet_config), Arc::new(wallet));
    let _res = wallet_server.start();
}
