#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(incomplete_features, clippy::extra_unused_type_parameters)]
#![feature(io_error_other)]
#![feature(async_fn_in_trait)]
// background file is mostly an LDK copy paste
mod background;

mod auth;
mod chain;
mod encrypt;
pub mod error;
pub mod esplora;
mod event;
mod fees;
mod gossip;
mod indexed_db;
mod keymanager;
mod ldkstorage;
mod logging;
mod lspclient;
mod node;
pub mod nodemanager;
mod onchain;
mod peermanager;
mod proxy;
pub mod redshift;
mod socket;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
mod utils;

use crate::error::MutinyError;
use crate::nodemanager::NodeManager;
pub use auth::AuthProfile;
use bip39::Mnemonic;
use bitcoin::Network;
use std::sync::Arc;

#[derive(Clone)]
pub struct MutinyWalletConfig {
    password: String,
    mnemonic: Option<Mnemonic>,
    websocket_proxy_addr: Option<String>,
    network: Option<Network>,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
}

impl MutinyWalletConfig {
    pub fn new(
        password: String,
        mnemonic: Option<Mnemonic>,
        websocket_proxy_addr: Option<String>,
        network: Option<Network>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
    ) -> Self {
        Self {
            password,
            mnemonic,
            websocket_proxy_addr,
            network,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
        }
    }
}

#[derive(Clone)]
/// MutinyWallet is the main entry point for the library.
/// It contains the NodeManager, which is the main interface to manage the
/// bitcoin and the lightning functionality.
pub struct MutinyWallet {
    config: MutinyWalletConfig,
    pub node_manager: Arc<NodeManager>,
}

impl MutinyWallet {
    pub async fn new(
        password: String,
        mnemonic: Option<Mnemonic>,
        websocket_proxy_addr: Option<String>,
        network: Option<Network>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
    ) -> Result<MutinyWallet, MutinyError> {
        let config = MutinyWalletConfig::new(
            password,
            mnemonic,
            websocket_proxy_addr,
            network,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
        );

        let node_manager = Arc::new(NodeManager::new(config.clone()).await?);

        NodeManager::start_redshifts(node_manager.clone());

        Ok(Self {
            config,
            node_manager,
        })
    }

    /// Starts up all the nodes again.
    /// Not needed after [NodeManager]'s `new()` function.
    pub async fn start(&mut self) -> Result<(), MutinyError> {
        self.node_manager = Arc::new(NodeManager::new(self.config.clone()).await?);
        NodeManager::start_redshifts(self.node_manager.clone());
        Ok(())
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    pub async fn stop(&self) -> Result<(), MutinyError> {
        // TODO stop redshift as well
        self.node_manager.stop().await
    }
}

#[cfg(test)]
mod tests {
    use crate::{nodemanager::NodeManager, MutinyWallet};
    use bitcoin::Network;

    use crate::test_utils::*;

    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        log!("creating mutiny wallet!");
        cleanup_wallet_test().await;

        assert!(!NodeManager::has_node_manager().await);
        MutinyWallet::new(
            "".to_string(),
            None,
            None,
            Some(Network::Testnet),
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        assert!(NodeManager::has_node_manager().await);

        cleanup_wallet_test().await;
    }

    #[test]
    async fn restart_mutiny_wallet() {
        log!("restarting mutiny wallet!");
        cleanup_wallet_test().await;

        assert!(!NodeManager::has_node_manager().await);
        let mut mw = MutinyWallet::new(
            "".to_string(),
            None,
            None,
            Some(Network::Testnet),
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        assert!(NodeManager::has_node_manager().await);

        let first_seed = mw.node_manager.show_seed();

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert_eq!(first_seed, mw.node_manager.show_seed());

        cleanup_wallet_test().await;
    }

    #[test]
    async fn restart_mutiny_wallet_with_nodes() {
        log!("restarting mutiny wallet with nodes!");
        cleanup_wallet_test().await;

        assert!(!NodeManager::has_node_manager().await);
        let mut mw = MutinyWallet::new(
            "".to_string(),
            None,
            None,
            Some(Network::Testnet),
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        assert!(NodeManager::has_node_manager().await);

        assert!(mw.node_manager.list_nodes().await.unwrap().is_empty());
        assert!(mw.node_manager.new_node().await.is_ok());
        assert!(!mw.node_manager.list_nodes().await.unwrap().is_empty());

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert!(!mw.node_manager.list_nodes().await.unwrap().is_empty());

        cleanup_wallet_test().await;
    }
}
