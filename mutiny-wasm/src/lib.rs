// wasm is considered "extra_unused_type_parameters"
#![allow(
    incomplete_features,
    clippy::extra_unused_type_parameters,
    clippy::arc_with_non_send_sync
)]

extern crate mutiny_core;

pub mod error;
mod indexed_db;
mod models;
mod utils;
pub mod waila;

use crate::error::MutinyJsError;
use crate::indexed_db::IndexedDbStorage;
use crate::models::*;
use bip39::Mnemonic;
use bitcoin::bip32::ExtendedPrivKey;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, OutPoint, Txid};
use fedimint_core::{api::InviteCode, config::FederationId};
use futures::lock::Mutex;
use gloo_utils::format::JsValueSerdeExt;
use hex_conservative::DisplayHex;
use lightning::{log_error, log_info, log_warn, routing::gossip::NodeId, util::logger::Logger};
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use moksha_core::token::TokenV3;
use mutiny_core::auth::MutinyAuthClient;
use mutiny_core::lnurlauth::AuthManager;
use mutiny_core::nostr::nip49::NIP49URI;
use mutiny_core::nostr::nwc::{BudgetedSpendingConditions, NwcProfileTag, SpendingConditions};
use mutiny_core::nostr::NostrKeySource;
use mutiny_core::storage::{DeviceLock, MutinyStorage, DEVICE_LOCK_KEY};
use mutiny_core::utils::{now, parse_npub, parse_npub_or_nip05, sleep, spawn};
use mutiny_core::vss::MutinyVssClient;
use mutiny_core::{
    encrypt::encryption_key_from_pass, InvoiceHandler, MutinyWalletConfigBuilder, PrivacyLevel,
};
use mutiny_core::{labels::Contact, MutinyWalletBuilder};
use mutiny_core::{
    labels::LabelStorage,
    nodemanager::{create_lsp_config, NodeManager},
};
use mutiny_core::{logging::MutinyLogger, lsp::LspConfig, nostr::ProfileType};
use nostr::prelude::Method;
use nostr::{Keys, ToBech32};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

static INITIALIZED: once_cell::sync::Lazy<Mutex<bool>> =
    once_cell::sync::Lazy::new(|| Mutex::new(false));

#[cfg(test)]
async fn uninit() {
    let mut init = INITIALIZED.lock().await;
    *init = false;
}

#[wasm_bindgen]
pub struct MutinyWallet {
    mnemonic: Mnemonic,
    inner: mutiny_core::MutinyWallet<IndexedDbStorage>,
}

/// The [MutinyWallet] is the main entry point for interacting with the Mutiny Wallet.
/// It is responsible for managing the on-chain wallet and the lightning nodes.
///
/// It can be used to create a new wallet, or to load an existing wallet.
///
/// It can be configured to use all different custom backend services, or to use the default
/// services provided by Mutiny.
#[wasm_bindgen]
impl MutinyWallet {
    /// Creates a new [MutinyWallet] with the given parameters.
    /// The mnemonic seed is read from storage, unless one is provided.
    /// If no mnemonic is provided, a new one is generated and stored.
    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        password: Option<String>,
        mnemonic_str: Option<String>,
        websocket_proxy_addr: Option<String>,
        network_str: Option<String>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
        lsp_connection_string: Option<String>,
        lsp_token: Option<String>,
        auth_url: Option<String>,
        subscription_url: Option<String>,
        storage_url: Option<String>,
        scorer_url: Option<String>,
        do_not_connect_peers: Option<bool>,
        skip_device_lock: Option<bool>,
        safe_mode: Option<bool>,
        skip_hodl_invoices: Option<bool>,
        nsec_override: Option<String>,
        nip_07_key: Option<String>,
        primal_url: Option<String>,
        blind_auth_url: Option<String>,
        hermes_url: Option<String>,
    ) -> Result<MutinyWallet, MutinyJsError> {
        let start = instant::Instant::now();
        // if both are set throw an error
        // todo default to nsec if both are for same key?
        if nsec_override.is_some() && nip_07_key.is_some() {
            return Err(MutinyJsError::InvalidArgumentsError);
        }

        utils::set_panic_hook();
        let mut init = INITIALIZED.lock().await;
        if *init {
            return Err(MutinyJsError::AlreadyRunning);
        } else {
            *init = true;
        }

        match Self::new_internal(
            password,
            mnemonic_str,
            websocket_proxy_addr,
            network_str,
            user_esplora_url,
            user_rgs_url,
            lsp_url,
            lsp_connection_string,
            lsp_token,
            auth_url,
            subscription_url,
            storage_url,
            scorer_url,
            do_not_connect_peers,
            skip_device_lock,
            safe_mode,
            skip_hodl_invoices,
            nsec_override,
            nip_07_key,
            primal_url,
            blind_auth_url,
            hermes_url,
        )
        .await
        {
            Ok(m) => {
                log_info!(
                    m.inner.logger,
                    "Wallet startup took {}ms",
                    start.elapsed().as_millis()
                );
                Ok(m)
            }
            Err(e) => {
                // mark uninitialized because we failed to startup
                *init = false;
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn new_internal(
        password: Option<String>,
        mnemonic_str: Option<String>,
        websocket_proxy_addr: Option<String>,
        network_str: Option<String>,
        user_esplora_url: Option<String>,
        user_rgs_url: Option<String>,
        lsp_url: Option<String>,
        lsp_connection_string: Option<String>,
        lsp_token: Option<String>,
        auth_url: Option<String>,
        subscription_url: Option<String>,
        storage_url: Option<String>,
        scorer_url: Option<String>,
        do_not_connect_peers: Option<bool>,
        skip_device_lock: Option<bool>,
        safe_mode: Option<bool>,
        skip_hodl_invoices: Option<bool>,
        nsec_override: Option<String>,
        nip_07_key: Option<String>,
        primal_url: Option<String>,
        blind_auth_url: Option<String>,
        hermes_url: Option<String>,
    ) -> Result<MutinyWallet, MutinyJsError> {
        let safe_mode = safe_mode.unwrap_or(false);
        let logger = Arc::new(MutinyLogger::default());

        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;

        let network: Network = network_str
            .map(|s| s.parse().expect("Invalid network"))
            .unwrap_or(Network::Bitcoin);

        let override_mnemonic = mnemonic_str.map(|s| Mnemonic::from_str(&s)).transpose()?;

        let mnemonic =
            IndexedDbStorage::get_mnemonic(override_mnemonic, password.as_deref(), cipher.clone())
                .await?;

        let seed = mnemonic.to_seed("");
        let xprivkey = ExtendedPrivKey::new_master(network, &seed).unwrap();

        let (auth_client, vss_client) = if safe_mode {
            (None, None)
        } else if let Some(auth_url) = auth_url.clone() {
            let auth_manager = AuthManager::new(xprivkey).unwrap();

            let lnurl_client = Arc::new(
                lnurl::Builder::default()
                    .build_async()
                    .expect("failed to make lnurl client"),
            );

            let auth_client = Arc::new(MutinyAuthClient::new(
                auth_manager,
                lnurl_client,
                logger.clone(),
                auth_url,
            ));

            // immediately start fetching JWT
            let auth = auth_client.clone();
            let logger_clone = logger.clone();
            spawn(async move {
                // if this errors, it's okay, we'll call it again when we fetch vss
                if let Err(e) = auth.authenticate().await {
                    log_warn!(
                        logger_clone,
                        "Failed to authenticate on startup, will retry on next call: {e}"
                    );
                }
            });

            let vss = storage_url.map(|url| {
                Arc::new(MutinyVssClient::new_authenticated(
                    auth_client.clone(),
                    url,
                    xprivkey.private_key,
                    logger.clone(),
                ))
            });

            (Some(auth_client), vss)
        } else {
            let vss = storage_url.map(|url| {
                Arc::new(MutinyVssClient::new_unauthenticated(
                    url,
                    xprivkey.private_key,
                    logger.clone(),
                ))
            });

            (None, vss)
        };

        let storage = IndexedDbStorage::new(password, cipher, vss_client, logger.clone()).await?;

        let mut config_builder = MutinyWalletConfigBuilder::new(xprivkey).with_network(network);
        if let Some(w) = websocket_proxy_addr {
            config_builder.with_websocket_proxy_addr(w);
        }
        if let Some(url) = user_esplora_url {
            config_builder.with_user_esplora_url(url);
        }
        if let Some(url) = user_rgs_url {
            config_builder.with_user_rgs_url(url);
        }
        if let Some(url) = lsp_url {
            config_builder.with_lsp_url(url);
        }
        if let Some(url) = lsp_connection_string {
            config_builder.with_lsp_connection_string(url);
        }
        if let Some(url) = lsp_token {
            config_builder.with_lsp_token(url);
        }
        if let Some(a) = auth_client {
            config_builder.with_auth_client(a);
        }
        if let Some(url) = subscription_url {
            config_builder.with_subscription_url(url);
        }
        if let Some(url) = scorer_url {
            config_builder.with_scorer_url(url);
        }
        if let Some(url) = primal_url {
            config_builder.with_primal_url(url);
        }
        if let Some(url) = blind_auth_url {
            config_builder.with_blind_auth_url(url);
        }
        if let Some(url) = hermes_url {
            config_builder.with_hermes_url(url);
        }
        if let Some(true) = skip_device_lock {
            config_builder.with_skip_device_lock();
        }
        if let Some(false) = skip_hodl_invoices {
            config_builder.do_not_skip_hodl_invoices();
        }
        if let Some(true) = do_not_connect_peers {
            config_builder.do_not_connect_peers();
        }
        if safe_mode {
            config_builder.with_safe_mode();
        }
        let config = config_builder.build();

        let mut mw_builder = MutinyWalletBuilder::new(xprivkey, storage).with_config(config);
        mw_builder.with_session_id(logger.session_id.clone());
        if let Some(nsec) = nsec_override {
            let keys = Keys::parse(nsec).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
            mw_builder.with_nostr_key_source(NostrKeySource::Imported(keys));
        }
        if let Some(key) = nip_07_key {
            let npub = parse_npub(&key)?;
            mw_builder.with_nostr_key_source(NostrKeySource::Extension(npub));
        }
        let inner = mw_builder.build().await?;

        Ok(MutinyWallet { mnemonic, inner })
    }

    pub fn is_safe_mode(&self) -> bool {
        self.inner.is_safe_mode()
    }

    /// Returns if there is a saved wallet in storage.
    /// This is checked by seeing if a mnemonic seed exists in storage.
    #[wasm_bindgen]
    pub async fn has_node_manager() -> Result<bool, MutinyJsError> {
        Ok(IndexedDbStorage::has_mnemonic().await?)
    }

    /// Returns the number of remaining seconds until the device lock expires.
    #[wasm_bindgen]
    pub async fn get_device_lock_remaining_secs(
        password: Option<String>,
        auth_url: Option<String>,
        storage_url: Option<String>,
    ) -> Result<Option<u64>, MutinyJsError> {
        let logger = Arc::new(MutinyLogger::default());
        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;
        let mnemonic =
            IndexedDbStorage::get_mnemonic(None, password.as_deref(), cipher.clone()).await?;

        let seed = mnemonic.to_seed("");
        // Network doesn't matter here, only for encoding
        let xprivkey = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();

        let vss_client = if let Some(auth_url) = auth_url {
            let auth_manager = AuthManager::new(xprivkey).unwrap();

            let lnurl_client = Arc::new(
                lnurl::Builder::default()
                    .build_async()
                    .expect("failed to make lnurl client"),
            );

            let auth_client = Arc::new(MutinyAuthClient::new(
                auth_manager,
                lnurl_client,
                logger.clone(),
                auth_url,
            ));

            storage_url.map(|url| {
                Arc::new(MutinyVssClient::new_authenticated(
                    auth_client.clone(),
                    url,
                    xprivkey.private_key,
                    logger.clone(),
                ))
            })
        } else {
            storage_url.map(|url| {
                Arc::new(MutinyVssClient::new_unauthenticated(
                    url,
                    xprivkey.private_key,
                    logger.clone(),
                ))
            })
        };

        if let Some(vss) = vss_client {
            let obj = vss.get_object(DEVICE_LOCK_KEY).await?;
            let lock = serde_json::from_value::<DeviceLock>(obj.value)?;

            return Ok(Some(lock.remaining_secs()));
        };

        Ok(None)
    }

    /// Starts up all the nodes again.
    /// Not needed after [NodeManager]'s `new()` function.
    #[wasm_bindgen]
    pub async fn start(&mut self) -> Result<(), MutinyJsError> {
        Ok(self.inner.start().await?)
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    #[wasm_bindgen]
    pub async fn stop(&self) -> Result<(), MutinyJsError> {
        Ok(self.inner.node_manager.stop().await?)
    }

    /// Returns the mnemonic seed phrase for the wallet.
    #[wasm_bindgen]
    pub fn show_seed(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Returns the user's npub
    #[wasm_bindgen]
    pub async fn get_npub(&self) -> String {
        self.inner
            .nostr
            .get_npub()
            .await
            .to_bech32()
            .expect("bech32")
    }

    /// Export the user's nostr secret key if available
    #[wasm_bindgen]
    pub async fn export_nsec(&self) -> Option<String> {
        self.inner
            .nostr
            .export_nsec()
            .await
            .map(|s| s.to_bech32().expect("bech32"))
    }

    /// Change our active nostr keys to the given nsec
    #[wasm_bindgen]
    pub async fn change_nostr_keys(
        &self,
        nsec: Option<String>,
        extension_pk: Option<String>,
    ) -> Result<String, MutinyJsError> {
        let nsec = nsec
            .map(|n| Keys::parse(n).map_err(|_| MutinyJsError::InvalidArgumentsError))
            .transpose()?;

        let extension_pk = extension_pk.map(|p| parse_npub(&p)).transpose()?;

        if nsec.is_some() && extension_pk.is_some() {
            return Err(MutinyJsError::InvalidArgumentsError);
        }

        Ok(self
            .inner
            .change_nostr_keys(nsec, extension_pk)
            .await
            .map(|pk| pk.to_bech32().expect("bech32"))?)
    }

    /// Returns the network of the wallet.
    #[wasm_bindgen]
    pub fn get_network(&self) -> String {
        self.inner.get_network().to_string()
    }

    /// Gets a new bitcoin address from the wallet.
    /// Will generate a new address on every call.
    ///
    /// It is recommended to create a new address for every transaction.
    #[wasm_bindgen]
    pub async fn get_new_address(
        &self,
        labels: Vec<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyJsError> {
        let address = self.inner.create_address(labels.clone()).await?;
        Ok(MutinyBip21RawMaterials {
            address: address.to_string(),
            invoice: None,
            btc_amount: None,
            labels,
        })
    }

    /// Creates a BIP 21 invoice. This creates a new address and a lightning invoice.
    /// The lightning invoice may return errors related to the LSP. Check the error and
    /// fallback to `get_new_address` and warn the user that Lightning is not available.
    ///
    ///
    /// Errors that might be returned include:
    ///
    /// - [`MutinyJsError::LspGenericError`]: This is returned for various reasons, including if a
    ///   request to the LSP server fails for any reason, or if the server returns
    ///   a status other than 500 that can't be parsed into a `ProposalResponse`.
    ///
    /// - [`MutinyJsError::LspFundingError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message
    ///   stating "Cannot fund new channel at this time". This means that the LSP cannot support
    ///   a new channel at this time.
    ///
    /// - [`MutinyJsError::LspAmountTooHighError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message stating "Invoice
    ///   amount is too high". This means that the LSP cannot support the amount that the user
    ///   requested. The user should request a smaller amount from the LSP.
    ///
    /// - [`MutinyJsError::LspConnectionError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message that starts with
    ///   "Failed to connect to peer". This means that the LSP is not connected to our node.
    ///
    /// If the server returns a status of 500 with a different error message,
    /// a [`MutinyJsError::LspGenericError`] is returned.
    #[wasm_bindgen]
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyJsError> {
        Ok(self.inner.create_bip21(amount, labels).await?.into())
    }

    /// Sends an on-chain transaction to the given address.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    ///
    /// If a fee rate is not provided, one will be used from the fee estimator.
    #[wasm_bindgen]
    pub async fn send_to_address(
        &self,
        destination_address: String,
        amount: u64,
        labels: Vec<String>,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        let send_to =
            Address::from_str(&destination_address)?.require_network(self.inner.get_network())?;
        Ok(self
            .inner
            .send_to_address(send_to, amount, labels, fee_rate)
            .await?
            .to_string())
    }

    #[wasm_bindgen]
    pub async fn send_payjoin(
        &self,
        payjoin_uri: String,
        amount: u64, /* override the uri amount if desired */
        labels: Vec<String>,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        // I know walia parses `pj=` and `pjos=` but payjoin::Uri parses the whole bip21 uri
        let pj_uri = payjoin::Uri::try_from(payjoin_uri.as_str())
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        Ok(self
            .inner
            .node_manager
            .send_payjoin(pj_uri, amount, labels, fee_rate)
            .await?
            .to_string())
    }

    /// Sweeps all the funds from the wallet to the given address.
    /// The fee rate is in sat/vbyte.
    ///
    /// If a fee rate is not provided, one will be used from the fee estimator.
    #[wasm_bindgen]
    pub async fn sweep_wallet(
        &self,
        destination_address: String,
        labels: Vec<String>,
        fee_rate: Option<f32>,
    ) -> Result<String, MutinyJsError> {
        let send_to =
            Address::from_str(&destination_address)?.require_network(self.inner.get_network())?;
        Ok(self
            .inner
            .sweep_wallet(send_to, labels, fee_rate)
            .await?
            .to_string())
    }

    /// Estimates the onchain fee for a transaction sending to the given address.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub async fn estimate_tx_fee(
        &self,
        destination_address: String,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyJsError> {
        let addr = Address::from_str(&destination_address)?.assume_checked();
        Ok(self.inner.estimate_tx_fee(addr, amount, fee_rate).await?)
    }

    /// Estimates the onchain fee for a transaction sweep our on-chain balance
    /// to the given address.
    ///
    /// The fee rate is in sat/vbyte.
    pub async fn estimate_sweep_tx_fee(
        &self,
        destination_address: String,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyJsError> {
        let addr = Address::from_str(&destination_address)?.assume_checked();
        Ok(self.inner.estimate_sweep_tx_fee(addr, fee_rate).await?)
    }

    /// Estimates the onchain fee for a opening a lightning channel.
    /// The amount is in satoshis and the fee rate is in sat/vbyte.
    pub fn estimate_channel_open_fee(
        &self,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyJsError> {
        Ok(self
            .inner
            .node_manager
            .estimate_channel_open_fee(amount, fee_rate)?)
    }

    /// Estimates the onchain fee for sweeping our on-chain balance to open a lightning channel.
    /// The fee rate is in sat/vbyte.
    pub fn estimate_sweep_channel_open_fee(
        &self,
        fee_rate: Option<f32>,
    ) -> Result<u64, MutinyJsError> {
        Ok(self
            .inner
            .node_manager
            .estimate_sweep_channel_open_fee(fee_rate)?)
    }

    /// Estimates the lightning fee for a transaction. Amount is either from the invoice
    /// if one is available or a passed in amount (priority). It will try to predict either
    /// sending the payment through a federation or through lightning, depending on balances.
    /// The amount and fee is in satoshis.
    /// Returns None if it has no good way to calculate fee.
    pub async fn estimate_ln_fee(
        &self,
        invoice_str: Option<String>,
        amt_sats: Option<u64>,
    ) -> Result<Option<u64>, MutinyJsError> {
        let invoice = match invoice_str {
            Some(i) => Some(Bolt11Invoice::from_str(&i)?),
            None => None,
        };
        Ok(self
            .inner
            .estimate_ln_fee(invoice.as_ref(), amt_sats)
            .await?)
    }

    /// Bumps the given transaction by replacing the given tx with a transaction at
    /// the new given fee rate in sats/vbyte
    pub async fn bump_fee(&self, txid: String, fee_rate: f32) -> Result<String, MutinyJsError> {
        let txid = Txid::from_str(&txid)?;
        let result = self.inner.node_manager.bump_fee(txid, fee_rate).await?;

        Ok(result.to_string())
    }

    /// Checks if the given address has any transactions.
    /// If it does, it returns the details of the first transaction.
    ///
    /// This should be used to check if a payment has been made to an address.
    #[wasm_bindgen]
    pub async fn check_address(
        &self,
        address: String,
    ) -> Result<JsValue /* Option<TransactionDetails> */, MutinyJsError> {
        let address = Address::from_str(&address)?;
        Ok(JsValue::from_serde(
            &self.inner.node_manager.check_address(address).await?,
        )?)
    }

    /// Gets the details of a specific on-chain transaction.
    #[wasm_bindgen]
    pub fn get_transaction(
        &self,
        txid: String,
    ) -> Result<JsValue /* Option<TransactionDetails> */, MutinyJsError> {
        let txid = Txid::from_str(&txid)?;
        Ok(JsValue::from_serde(&self.inner.get_transaction(txid)?)?)
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain and lightning funds.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    #[wasm_bindgen]
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyJsError> {
        Ok(self.inner.get_balance().await?.into())
    }

    /// Lists all the UTXOs in the wallet.
    #[wasm_bindgen]
    pub fn list_utxos(&self) -> Result<JsValue, MutinyJsError> {
        Ok(JsValue::from_serde(&self.inner.node_manager.list_utxos()?)?)
    }

    /// Gets a fee estimate for an low priority transaction.
    /// Value is in sat/vbyte.
    #[wasm_bindgen]
    pub fn estimate_fee_low(&self) -> u32 {
        self.inner.node_manager.estimate_fee_low()
    }

    /// Gets a fee estimate for an average priority transaction.
    /// Value is in sat/vbyte.
    #[wasm_bindgen]
    pub fn estimate_fee_normal(&self) -> u32 {
        self.inner.node_manager.estimate_fee_normal()
    }

    /// Gets a fee estimate for an high priority transaction.
    /// Value is in sat/vbyte.
    #[wasm_bindgen]
    pub fn estimate_fee_high(&self) -> u32 {
        self.inner.node_manager.estimate_fee_high()
    }

    /// Creates a new lightning node and adds it to the manager.
    #[wasm_bindgen]
    pub async fn new_node(&self) -> Result<NodeIdentity, MutinyJsError> {
        Ok(self.inner.node_manager.new_node().await?.into())
    }

    /// Lists the pubkeys of the lightning node in the manager.
    #[wasm_bindgen]
    pub async fn list_nodes(&self) -> Result<JsValue /* Vec<String> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.list_nodes().await?,
        )?)
    }

    /// Changes all the node's LSPs to the given config. If any of the nodes have an active channel with the
    /// current LSP, it will fail to change the LSP.
    ///
    /// Requires a restart of the node manager to take effect.
    pub async fn change_lsp(
        &self,
        lsp_url: Option<String>,
        lsp_connection_string: Option<String>,
        lsp_token: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let lsp_config = create_lsp_config(lsp_url, lsp_connection_string, lsp_token)?;

        self.inner.node_manager.change_lsp(lsp_config).await?;
        Ok(())
    }

    /// Returns the current LSP config
    pub async fn get_configured_lsp(&self) -> Result<JsValue, MutinyJsError> {
        match self.inner.node_manager.get_configured_lsp().await? {
            Some(LspConfig::VoltageFlow(config)) => Ok(JsValue::from_serde(&config)?),
            Some(LspConfig::Lsps(config)) => Ok(JsValue::from_serde(&config)?),
            None => Ok(JsValue::NULL),
        }
    }

    /// Attempts to connect to a peer from the selected node.
    #[wasm_bindgen]
    pub async fn connect_to_peer(
        &self,
        connection_string: String,
        label: Option<String>,
    ) -> Result<(), MutinyJsError> {
        Ok(self
            .inner
            .node_manager
            .connect_to_peer(None, &connection_string, label)
            .await?)
    }

    /// Disconnects from a peer from the selected node.
    #[wasm_bindgen]
    pub async fn disconnect_peer(&self, peer: String) -> Result<(), MutinyJsError> {
        let peer = PublicKey::from_str(&peer)?;
        Ok(self.inner.node_manager.disconnect_peer(None, peer).await?)
    }

    /// Deletes a peer from the selected node.
    /// This will make it so that the node will not attempt to
    /// reconnect to the peer.
    #[wasm_bindgen]
    pub async fn delete_peer(&self, peer: String) -> Result<(), MutinyJsError> {
        let peer = NodeId::from_str(&peer).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        Ok(self.inner.node_manager.delete_peer(None, &peer).await?)
    }

    /// Sets the label of a peer from the selected node.
    #[wasm_bindgen]
    pub fn label_peer(&self, node_id: String, label: Option<String>) -> Result<(), MutinyJsError> {
        let node_id =
            NodeId::from_str(&node_id).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        self.inner.node_manager.label_peer(&node_id, label)?;
        Ok(())
    }

    /// Creates a lightning invoice. The amount should be in satoshis.
    /// If no amount is provided, the invoice will be created with no amount.
    /// If no description is provided, the invoice will be created with no description.
    ///
    /// If the manager has more than one node it will create a phantom invoice.
    /// If there is only one node it will create an invoice just for that node.
    #[wasm_bindgen]
    pub async fn create_invoice(
        &self,
        amount: u64,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self.inner.create_invoice(amount, labels).await?.into())
    }

    /// Pays a lightning invoice from the selected node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// The amount should be in satoshis.
    #[wasm_bindgen]
    pub async fn pay_invoice(
        &self,
        invoice_str: String,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice_str)?;
        Ok(self
            .inner
            .pay_invoice(&invoice, amt_sats, labels)
            .await?
            .into())
    }

    /// Sends a spontaneous payment to a node from the selected node.
    /// The amount should be in satoshis.
    #[wasm_bindgen]
    pub async fn keysend(
        &self,
        to_node: String,
        amt_sats: u64,
        message: Option<String>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let to_node = PublicKey::from_str(&to_node)?;
        Ok(self
            .inner
            .node_manager
            .keysend(None, to_node, amt_sats, message, labels)
            .await?
            .into())
    }

    /// Decodes a lightning invoice into useful information.
    /// Will return an error if the invoice is for a different network.
    #[wasm_bindgen]
    pub async fn decode_invoice(
        &self,
        invoice: String,
        network: Option<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice)?;
        let network = network
            .map(|n| Network::from_str(&n).map_err(|_| MutinyJsError::InvalidArgumentsError))
            .transpose()?;
        Ok(self.inner.decode_invoice(invoice, network)?.into())
    }

    /// Calls upon a LNURL to get the parameters for it.
    /// This contains what kind of LNURL it is (pay, withdrawal, auth, etc).
    #[wasm_bindgen]
    pub async fn decode_lnurl(&self, lnurl: String) -> Result<LnUrlParams, MutinyJsError> {
        let lnurl = LnUrl::from_str(&lnurl)?;
        Ok(self.inner.decode_lnurl(lnurl).await?.into())
    }

    /// Calls upon a LNURL and pays it.
    /// This will fail if the LNURL is not a LNURL pay.
    #[wasm_bindgen]
    pub async fn lnurl_pay(
        &self,
        lnurl: String,
        amount_sats: u64,
        zap_npub: Option<String>,
        labels: Vec<String>,
        comment: Option<String>,
        privacy_level: Option<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let lnurl = LnUrl::from_str(&lnurl)?;

        let zap_npub = match zap_npub.filter(|z| !z.is_empty()) {
            Some(z) => Some(parse_npub(&z)?),
            None => None,
        };

        let privacy_level = privacy_level
            .as_deref()
            .map(PrivacyLevel::from_str)
            .transpose()?
            .unwrap_or_default(); // default to NotAvailable

        Ok(self
            .inner
            .lnurl_pay(
                &lnurl,
                amount_sats,
                zap_npub,
                labels,
                comment,
                privacy_level,
            )
            .await?
            .into())
    }

    /// Calls upon a LNURL and withdraws from it.
    /// This will fail if the LNURL is not a LNURL withdrawal.
    #[wasm_bindgen]
    pub async fn lnurl_withdraw(
        &self,
        lnurl: String,
        amount_sats: u64,
    ) -> Result<bool, MutinyJsError> {
        let lnurl = LnUrl::from_str(&lnurl)?;
        Ok(self.inner.lnurl_withdraw(&lnurl, amount_sats).await?)
    }

    /// Calls upon a Cash mint and melts the token from it.
    #[wasm_bindgen]
    pub async fn melt_cashu_token(
        &self,
        maybe_token: String,
    ) -> Result<JsValue /* Vec<MutinyInvoice> */, MutinyJsError> {
        let token = TokenV3::deserialize(maybe_token)?;
        let result = self.inner.melt_cashu_token(token).await?;
        let invoices: Vec<MutinyInvoice> = result.into_iter().map(|i| i.into()).collect();
        Ok(JsValue::from_serde(&invoices)?)
    }

    /// Authenticates with a LNURL-auth for the given profile.
    #[wasm_bindgen]
    pub async fn lnurl_auth(&self, lnurl: String) -> Result<(), MutinyJsError> {
        let lnurl = LnUrl::from_str(&lnurl)?;
        Ok(self.inner.lnurl_auth(lnurl).await?)
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn get_invoice(&self, invoice: String) -> Result<MutinyInvoice, MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice)?;
        Ok(self.inner.get_invoice(&invoice).await?.into())
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn get_invoice_by_hash(&self, hash: String) -> Result<MutinyInvoice, MutinyJsError> {
        let hash: sha256::Hash = sha256::Hash::from_str(&hash)?;
        Ok(self.inner.get_invoice_by_hash(&hash).await?.into())
    }

    /// Gets an invoice from the node manager.
    /// This includes sent and received invoices.
    #[wasm_bindgen]
    pub async fn list_invoices(&self) -> Result<JsValue /* Vec<MutinyInvoice> */, MutinyJsError> {
        Ok(JsValue::from_serde(&self.inner.list_invoices()?)?)
    }

    /// Gets an channel closure from the node manager.
    #[wasm_bindgen]
    pub async fn get_channel_closure(
        &self,
        user_channel_id: String,
    ) -> Result<ChannelClosure, MutinyJsError> {
        let user_channel_id: [u8; 16] = FromHex::from_hex(&user_channel_id)?;
        Ok(self
            .inner
            .node_manager
            .get_channel_closure(u128::from_be_bytes(user_channel_id))
            .await?
            .into())
    }

    /// Gets all channel closures from the node manager.
    ///
    /// The channel closures are sorted by the time they were closed.
    #[wasm_bindgen]
    pub async fn list_channel_closures(
        &self,
    ) -> Result<JsValue /* Vec<ChannelClosure> */, MutinyJsError> {
        let mut channel_closures = self.inner.node_manager.list_channel_closures().await?;
        channel_closures.sort();
        Ok(JsValue::from_serde(&channel_closures)?)
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// The amount is in satoshis.
    ///
    /// The node must be online and have a connection to the peer.
    /// The wallet much have enough funds to open the channel.
    #[wasm_bindgen]
    pub async fn open_channel(
        &self,
        to_pubkey: Option<String>,
        amount: u64,
        fee_rate: Option<f32>,
    ) -> Result<MutinyChannel, MutinyJsError> {
        let to_pubkey = match to_pubkey {
            Some(pubkey_str) if !pubkey_str.trim().is_empty() => {
                Some(PublicKey::from_str(&pubkey_str)?)
            }
            _ => None,
        };

        Ok(self
            .inner
            .node_manager
            .open_channel(None, to_pubkey, amount, fee_rate, None)
            .await?
            .into())
    }

    /// Opens a channel from our selected node to the given pubkey.
    /// It will spend the all the on-chain utxo in full to fund the channel.
    ///
    /// The node must be online and have a connection to the peer.
    pub async fn sweep_all_to_channel(
        &self,
        to_pubkey: Option<String>,
    ) -> Result<MutinyChannel, MutinyJsError> {
        let to_pubkey = match to_pubkey {
            Some(pubkey_str) if !pubkey_str.trim().is_empty() => {
                Some(PublicKey::from_str(&pubkey_str)?)
            }
            _ => None,
        };

        Ok(self
            .inner
            .node_manager
            .sweep_all_to_channel(to_pubkey)
            .await?
            .into())
    }

    /// Sweep the federation balance into a lightning channel
    pub async fn sweep_federation_balance_to_invoice(
        &self,
        from_federation_id: Option<String>,
        bolt_11: String,
    ) -> Result<FedimintSweepResult, MutinyJsError> {
        let from_federation_id = match from_federation_id {
            Some(f) => {
                Some(FederationId::from_str(&f).map_err(|_| MutinyJsError::InvalidArgumentsError)?)
            }
            None => None,
        };

        let bolt_11 = Bolt11Invoice::from_str(&bolt_11)?;

        Ok(self
            .inner
            .sweep_federation_balance_to_invoice(from_federation_id, bolt_11)
            .await?
            .into())
    }

    /// Estimate the fee before trying to sweep from federation
    pub async fn create_sweep_federation_invoice(
        &self,
        amount: Option<u64>,
        from_federation_id: Option<String>,
        to_federation_id: Option<String>,
    ) -> Result<MutinyInvoice, MutinyJsError> {
        let from_federation_id = match from_federation_id {
            Some(f) => {
                Some(FederationId::from_str(&f).map_err(|_| MutinyJsError::InvalidArgumentsError)?)
            }
            None => None,
        };

        let to_federation_id = match to_federation_id {
            Some(f) => {
                Some(FederationId::from_str(&f).map_err(|_| MutinyJsError::InvalidArgumentsError)?)
            }
            None => None,
        };

        Ok(self
            .inner
            .create_sweep_federation_invoice(amount, from_federation_id, to_federation_id)
            .await?
            .into())
    }

    /// Closes a channel with the given outpoint.
    ///
    /// If force is true, the channel will be force closed.
    ///
    /// If abandon is true, the channel will be abandoned.
    /// This will force close without broadcasting the latest transaction.
    /// This should only be used if the channel will never actually be opened.
    ///
    /// If both force and abandon are true, an error will be returned.
    #[wasm_bindgen]
    pub async fn close_channel(
        &self,
        outpoint: String,
        force: bool,
        abandon: bool,
    ) -> Result<(), MutinyJsError> {
        let outpoint: OutPoint =
            OutPoint::from_str(&outpoint).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        Ok(self
            .inner
            .node_manager
            .close_channel(&outpoint, None, force, abandon)
            .await?)
    }

    /// Lists all the channels for all the nodes in the node manager.
    #[wasm_bindgen]
    pub async fn list_channels(&self) -> Result<JsValue /* Vec<MutinyChannel> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.list_channels().await?,
        )?)
    }

    /// Lists all the peers for all the nodes in the node manager.
    #[wasm_bindgen]
    pub async fn list_peers(&self) -> Result<JsValue /* Vec<MutinyPeer> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.list_peers().await?,
        )?)
    }

    /// Returns all the on-chain and lightning activity from the wallet.
    #[wasm_bindgen]
    pub async fn get_activity(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<JsValue /* Vec<ActivityItem> */, MutinyJsError> {
        // get activity from the node manager
        let activity = self.inner.get_activity(limit, offset)?;
        let mut activity: Vec<ActivityItem> = activity.into_iter().map(|a| a.into()).collect();

        // add contacts to the activity
        let contacts = self.inner.node_manager.get_contacts()?;
        let follows = self.inner.nostr.get_follow_list()?;
        for a in activity.iter_mut() {
            // find labels that have a contact and add them to the item
            for label in a.labels.iter() {
                if let Some(contact) = contacts.get(label) {
                    let is_followed = contact
                        .npub
                        .as_ref()
                        .map(|n| follows.contains(n))
                        .unwrap_or(false);
                    a.contacts
                        .push(TagItem::from(label.clone(), contact.clone(), is_followed));
                }
            }
            // remove labels that have a contact to prevent duplicates
            a.labels.retain(|l| !contacts.contains_key(l));
        }

        Ok(JsValue::from_serde(&activity)?)
    }

    /// Returns all the on-chain and lightning activity for a given label
    #[wasm_bindgen]
    pub async fn get_label_activity(
        &self,
        label: String,
    ) -> Result<JsValue /* Vec<ActivityItem> */, MutinyJsError> {
        // get activity from the node manager
        let activity = self.inner.get_label_activity(&label).await?;
        let mut activity: Vec<ActivityItem> = activity.into_iter().map(|a| a.into()).collect();

        // add contact to the activity item it has one, otherwise return the activity list
        let contact = match self.inner.node_manager.get_contact(&label)? {
            Some(contact) => contact,
            None => return Ok(JsValue::from_serde(&activity)?),
        };

        let follows = self.inner.nostr.get_follow_list()?;
        let is_followed = contact
            .npub
            .as_ref()
            .map(|n| follows.contains(n))
            .unwrap_or(false);

        // if we have a contact, add it to the activity item, remove it as a label
        // This is the same as we do in get_activity
        for a in activity.iter_mut() {
            a.contacts
                .push(TagItem::from(label.clone(), contact.clone(), is_followed));
            a.labels.retain(|l| l != &label);
        }

        Ok(JsValue::from_serde(&activity)?)
    }

    /// Adds a new federation based on its federation code
    #[wasm_bindgen]
    pub async fn new_federation(
        &mut self,
        federation_code: String,
    ) -> Result<FederationIdentity, MutinyJsError> {
        Ok(self
            .inner
            .new_federation(InviteCode::from_str(&federation_code).map_err(|e| {
                log_error!(
                    self.inner.logger,
                    "Error parsing federation code ({federation_code}): {e}"
                );
                MutinyJsError::InvalidArgumentsError
            })?)
            .await?
            .into())
    }

    /// Lists the federation id's of the federation clients in the manager.
    #[wasm_bindgen]
    pub async fn list_federations(
        &self,
    ) -> Result<JsValue /* Vec<FederationIdentity> */, MutinyJsError> {
        Ok(JsValue::from_serde(&self.inner.list_federations().await?)?)
    }

    /// Removes a federation by setting its archived status to true, based on the FederationId.
    #[wasm_bindgen]
    pub async fn remove_federation(&self, federation_id: String) -> Result<(), MutinyJsError> {
        Ok(self
            .inner
            .remove_federation(
                FederationId::from_str(&federation_id)
                    .map_err(|_| MutinyJsError::InvalidArgumentsError)?,
            )
            .await?)
    }

    /// Gets the current balances of each federation.
    #[wasm_bindgen]
    pub async fn get_federation_balances(&self) -> Result<FederationBalances, MutinyJsError> {
        Ok(self.inner.get_federation_balances().await?.into())
    }

    /// Creates a recommendation event for a federation
    pub async fn recommend_federation(
        &self,
        invite_code: String,
        review: Option<String>,
    ) -> Result<String, MutinyJsError> {
        let invite_code =
            InviteCode::from_str(&invite_code).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        let event_id = self
            .inner
            .nostr
            .recommend_federation(&invite_code, self.inner.get_network(), review.as_deref())
            .await?;
        Ok(event_id.to_hex())
    }

    /// Checks if we have recommended the given federation
    pub async fn has_recommended_federation(
        &self,
        federation_id: String,
    ) -> Result<bool, MutinyJsError> {
        let federation_id = FederationId::from_str(&federation_id)
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        Ok(self
            .inner
            .nostr
            .has_recommended_federation(&federation_id)
            .await?)
    }

    /// Creates a delete event for a federation recommendation
    pub async fn delete_federation_recommendation(
        &self,
        federation_id: String,
    ) -> Result<(), MutinyJsError> {
        let federation_id = FederationId::from_str(&federation_id)
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        Ok(self
            .inner
            .nostr
            .delete_federation_recommendation(&federation_id)
            .await?)
    }

    /// Queries our relays for federation announcements
    pub async fn discover_federations(
        &self,
    ) -> Result<JsValue /* Vec<NostrDiscoveredFedimint> */, MutinyJsError> {
        let federations = self
            .inner
            .nostr
            .discover_federations(self.inner.get_network())
            .await?;
        Ok(JsValue::from_serde(&federations)?)
    }

    pub fn get_address_labels(
        &self,
    ) -> Result<JsValue /* Map<Address, Vec<String>> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.get_address_labels()?,
        )?)
    }

    /// Set the labels for an address, replacing any existing labels
    /// If you want to do not want to replace any existing labels, use `get_address_labels` to get the existing labels,
    /// add the new labels, and then use `set_address_labels` to set the new labels
    pub fn set_address_labels(
        &self,
        address: String,
        labels: Vec<String>,
    ) -> Result<(), MutinyJsError> {
        let address = Address::from_str(&address)?.assume_checked();
        Ok(self
            .inner
            .node_manager
            .set_address_labels(address, labels)?)
    }

    pub fn get_invoice_labels(
        &self,
    ) -> Result<JsValue /* Map<Invoice, Vec<String>> */, MutinyJsError> {
        Ok(JsValue::from_serde(
            &self.inner.node_manager.get_invoice_labels()?,
        )?)
    }

    /// Set the labels for an invoice, replacing any existing labels
    /// If you want to do not want to replace any existing labels, use `get_invoice_labels` to get the existing labels,
    /// add the new labels, and then use `set_invoice_labels` to set the new labels
    pub fn set_invoice_labels(
        &self,
        invoice: String,
        labels: Vec<String>,
    ) -> Result<(), MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice)?;
        Ok(self
            .inner
            .node_manager
            .set_invoice_labels(invoice, labels)?)
    }

    pub async fn get_contacts(&self) -> Result<JsValue /* Map<String, TagItem>*/, MutinyJsError> {
        let follows = self.inner.nostr.get_follow_list()?;
        Ok(JsValue::from_serde(
            &self
                .inner
                .node_manager
                .get_contacts()?
                .into_iter()
                .map(|(id, c)| {
                    let is_followed = c
                        .npub
                        .as_ref()
                        .map(|n| follows.contains(n))
                        .unwrap_or(false);
                    (id.clone(), TagItem::from(id, c, is_followed))
                })
                .collect::<HashMap<String, TagItem>>(),
        )?)
    }

    /// Gets all contacts sorted by last used
    pub async fn get_contacts_sorted(&self) -> Result<JsValue /* Vec<TagItem>*/, MutinyJsError> {
        let follows = self.inner.nostr.get_follow_list()?;
        let mut contacts: Vec<TagItem> = self
            .inner
            .node_manager
            .get_contacts()?
            .into_iter()
            .map(|(id, c)| {
                let is_followed = c
                    .npub
                    .as_ref()
                    .map(|n| follows.contains(n))
                    .unwrap_or(false);
                TagItem::from(id, c, is_followed)
            })
            .collect();

        contacts.sort();

        Ok(JsValue::from_serde(&contacts)?)
    }

    /// Get the contacts that are followed by the user sorted by last used
    pub async fn get_follows_sorted(&self) -> Result<JsValue /* Vec<TagItem>*/, MutinyJsError> {
        let follows = self.inner.nostr.get_follow_list()?;
        let mut contacts: Vec<TagItem> = self
            .inner
            .node_manager
            .get_contacts()?
            .into_iter()
            .flat_map(|(id, c)| {
                let is_followed = c
                    .npub
                    .as_ref()
                    .map(|n| follows.contains(n))
                    .unwrap_or(false);
                if is_followed {
                    Some(TagItem::from(id, c, is_followed))
                } else {
                    None
                }
            })
            .collect();

        contacts.sort();

        Ok(JsValue::from_serde(&contacts)?)
    }

    pub fn get_tag_item(&self, label: String) -> Result<Option<TagItem>, MutinyJsError> {
        match self.inner.node_manager.get_contact(&label)? {
            Some(contact) => {
                let follows = self.inner.nostr.get_follow_list()?;
                let is_followed = contact
                    .npub
                    .as_ref()
                    .map(|n| follows.contains(n))
                    .unwrap_or(false);
                Ok(Some(TagItem::from(label, contact, is_followed)))
            }
            None => Ok(None),
        }
    }

    /// Create a new contact from an existing label and returns the new identifying label
    pub fn create_contact_from_label(
        &self,
        label: String,
        name: String,
        npub: Option<String>,
        ln_address: Option<String>,
        lnurl: Option<String>,
        image_url: Option<String>,
    ) -> Result<String, MutinyJsError> {
        let contact = Contact {
            name,
            npub: npub.map(|n| parse_npub(&n)).transpose()?,
            ln_address: ln_address
                .map(|l| LightningAddress::from_str(&l))
                .transpose()?,
            lnurl: lnurl.map(|l| LnUrl::from_str(&l)).transpose()?,
            image_url,
            last_used: now().as_secs(),
        };

        Ok(self
            .inner
            .node_manager
            .create_contact_from_label(label, contact)?)
    }

    pub fn create_new_contact(
        &self,
        name: String,
        npub: Option<String>,
        ln_address: Option<String>,
        lnurl: Option<String>,
        image_url: Option<String>,
    ) -> Result<String, MutinyJsError> {
        let contact = Contact {
            name,
            npub: npub.map(|n| parse_npub(&n)).transpose()?,
            ln_address: ln_address
                .map(|l| LightningAddress::from_str(&l))
                .transpose()?,
            lnurl: lnurl.map(|l| LnUrl::from_str(&l)).transpose()?,
            image_url,
            last_used: now().as_secs(),
        };
        Ok(self.inner.node_manager.create_new_contact(contact)?)
    }

    pub fn delete_contact(&self, id: String) -> Result<(), MutinyJsError> {
        Ok(self.inner.node_manager.delete_contact(id)?)
    }

    pub fn edit_contact(
        &self,
        id: String,
        name: String,
        npub: Option<String>,
        ln_address: Option<String>,
        lnurl: Option<String>,
        image_url: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let contact = Contact {
            name,
            npub: npub.map(|n| parse_npub(&n)).transpose()?,
            ln_address: ln_address
                .map(|l| LightningAddress::from_str(&l))
                .transpose()?,
            lnurl: lnurl.map(|l| LnUrl::from_str(&l)).transpose()?,
            image_url,
            last_used: now().as_secs(),
        };

        Ok(self.inner.node_manager.edit_contact(id, contact)?)
    }

    pub async fn get_contact_for_npub(
        &self,
        npub: String,
    ) -> Result<Option<TagItem>, MutinyJsError> {
        let npub = parse_npub(&npub)?;
        let contact = self.inner.node_manager.get_contact_for_npub(npub)?;

        match contact {
            Some((id, c)) => {
                let follows = self.inner.nostr.get_follow_list()?;
                let is_followed = c
                    .npub
                    .as_ref()
                    .map(|n| follows.contains(n))
                    .unwrap_or(false);
                Ok(Some(TagItem::from(id, c, is_followed)))
            }
            None => Ok(None),
        }
    }

    pub fn get_tag_items(&self) -> Result<Vec<TagItem>, MutinyJsError> {
        let mut tags: Vec<TagItem> = self
            .inner
            .node_manager
            .get_tag_items()?
            .into_iter()
            .map(|t| t.into())
            .collect();

        tags.sort();

        Ok(tags)
    }

    /// Gets the current bitcoin price in chosen Fiat.
    #[wasm_bindgen]
    pub async fn get_bitcoin_price(&self, fiat: Option<String>) -> Result<f32, MutinyJsError> {
        Ok(self.inner.get_bitcoin_price(fiat).await?)
    }

    /// Exports the current state of the node manager to a json object.
    #[wasm_bindgen]
    pub async fn get_logs() -> Result<JsValue /* Option<Vec<String>> */, MutinyJsError> {
        let logs = IndexedDbStorage::get_logs().await?;
        Ok(JsValue::from_serde(&logs)?)
    }

    /// Get nostr wallet connect profiles
    #[wasm_bindgen]
    pub fn get_nwc_profiles(&self) -> Result<Vec<NwcProfile>, MutinyJsError> {
        let profiles = self.inner.nostr.profiles();
        let p = profiles
            .into_iter()
            .map(models::NwcProfile::from)
            .collect::<Vec<_>>();
        Ok(p)
    }

    /// Create a nostr wallet connect profile
    #[wasm_bindgen]
    pub async fn create_nwc_profile(
        &self,
        name: String,
        commands: Option<Vec<String>>,
    ) -> Result<models::NwcProfile, MutinyJsError> {
        let commands = match commands {
            None => vec![
                Method::PayInvoice,
                Method::GetInfo,
                Method::GetBalance,
                Method::LookupInvoice,
                Method::MakeInvoice,
            ],
            Some(strs) => strs
                .into_iter()
                .map(|s| Method::from_str(&s))
                .collect::<Result<_, _>>()
                .map_err(|_| MutinyJsError::InvalidArgumentsError)?,
        };
        Ok(self
            .inner
            .nostr
            .create_new_nwc_profile(
                ProfileType::Normal { name },
                SpendingConditions::default(),
                NwcProfileTag::General,
                commands,
            )
            .await?
            .into())
    }

    /// Create a budgeted nostr wallet connect profile
    #[wasm_bindgen]
    pub async fn create_budget_nwc_profile(
        &self,
        name: String,
        budget: u64,
        period: BudgetPeriod,
        single_max: Option<u64>,
        commands: Option<Vec<String>>,
    ) -> Result<models::NwcProfile, MutinyJsError> {
        let commands = match commands {
            None => vec![
                Method::PayInvoice,
                Method::GetInfo,
                Method::GetBalance,
                Method::LookupInvoice,
                Method::MakeInvoice,
            ],
            Some(strs) => strs
                .into_iter()
                .map(|s| Method::from_str(&s))
                .collect::<Result<_, _>>()
                .map_err(|_| MutinyJsError::InvalidArgumentsError)?,
        };
        let budget = BudgetedSpendingConditions {
            budget,
            period: period.into(),
            payments: vec![],
            single_max,
        };
        let sp = SpendingConditions::Budget(budget);

        Ok(self
            .inner
            .nostr
            .create_new_nwc_profile(
                ProfileType::Normal { name },
                sp,
                NwcProfileTag::General,
                commands,
            )
            .await?
            .into())
    }

    /// Approves a nostr wallet auth request.
    /// Creates a new NWC profile and saves to storage.
    /// This will also broadcast the info event to the relay.
    pub async fn approve_nostr_wallet_auth(
        &self,
        name: String,
        uri: String,
    ) -> Result<NwcProfile, MutinyJsError> {
        let uri = NIP49URI::from_str(&uri).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        log::info!("Approving NWC auth request: {uri}");
        let profile = self
            .inner
            .nostr
            .approve_nostr_wallet_auth(
                ProfileType::Normal { name },
                uri,
                None,
                NwcProfileTag::General,
            )
            .await?;

        Ok(profile.into())
    }

    /// Approves a nostr wallet auth request.
    /// Creates a new NWC profile and saves to storage.
    /// This will also broadcast the info event to the relay.
    pub async fn approve_nostr_wallet_auth_with_budget(
        &self,
        name: String,
        uri: String,
        budget: u64,
        period: BudgetPeriod,
    ) -> Result<NwcProfile, MutinyJsError> {
        let uri = NIP49URI::from_str(&uri).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        log::info!("Approving NWC auth request: {uri}");

        let budget = BudgetedSpendingConditions {
            budget,
            period: period.into(),
            payments: vec![],
            single_max: None,
        };

        let profile = self
            .inner
            .nostr
            .approve_nostr_wallet_auth(
                ProfileType::Normal { name },
                uri,
                Some(budget),
                NwcProfileTag::General,
            )
            .await?;

        Ok(profile.into())
    }

    /// Deletes a nostr wallet connect profile
    #[wasm_bindgen]
    pub async fn delete_nwc_profile(&self, profile_index: u32) -> Result<(), MutinyJsError> {
        Ok(self.inner.nostr.delete_nwc_profile(profile_index)?)
    }

    /// Re-enables a disabled nwc profile
    pub async fn enable_nwc_profile(&self, index: u32) -> Result<(), MutinyJsError> {
        self.inner.nostr.enable_nwc_profile(index)?;
        Ok(())
    }

    /// Set budget for a NWC Profile
    #[wasm_bindgen]
    pub async fn set_nwc_profile_budget(
        &self,
        profile_index: u32,
        budget_sats: u64,
        period: BudgetPeriod,
        single_max_sats: Option<u64>,
    ) -> Result<models::NwcProfile, MutinyJsError> {
        Ok(self
            .inner
            .nostr
            .set_nwc_profile_budget(profile_index, budget_sats, period.into(), single_max_sats)?
            .into())
    }

    /// Require approval for a NWC Profile
    #[wasm_bindgen]
    pub async fn set_nwc_profile_require_approval(
        &self,
        profile_index: u32,
    ) -> Result<models::NwcProfile, MutinyJsError> {
        let mut profile = self.inner.nostr.get_nwc_profile(profile_index)?;
        profile.spending_conditions = SpendingConditions::RequireApproval;
        Ok(self.inner.nostr.edit_nwc_profile(profile)?.into())
    }

    /// Finds a nostr wallet connect profile by index
    #[wasm_bindgen]
    pub async fn get_nwc_profile(&self, index: u32) -> Result<models::NwcProfile, MutinyJsError> {
        Ok(self.inner.nostr.get_nwc_profile(index)?.into())
    }

    /// Create a single use nostr wallet connect profile
    #[wasm_bindgen]
    pub async fn create_single_use_nwc(
        &self,
        name: String,
        amount_sats: u64,
    ) -> Result<models::NwcProfile, MutinyJsError> {
        Ok(self
            .inner
            .nostr
            .create_single_use_nwc(name, amount_sats)
            .await?
            .into())
    }

    /// Create a single use nostr wallet connect profile
    #[wasm_bindgen]
    pub async fn claim_single_use_nwc(
        &self,
        amount_sats: u64,
        nwc_uri: String,
    ) -> Result<Option<String>, MutinyJsError> {
        Ok(self
            .inner
            .nostr
            .claim_single_use_nwc(amount_sats, &nwc_uri, &self.inner)
            .await?
            .map(|r| r.message))
    }

    /// Get nostr wallet connect URI
    #[wasm_bindgen]
    pub fn get_nwc_uri(&self, index: u32) -> Result<Option<String>, MutinyJsError> {
        match self.inner.nostr.get_nwc_uri(index) {
            Ok(uri) => Ok(uri.map(|u| u.to_string())),
            Err(e) => Err(e.into()),
        }
    }

    /// Lists all pending NWC invoices
    pub fn get_pending_nwc_invoices(&self) -> Result<Vec<PendingNwcInvoice>, MutinyJsError> {
        let pending = self.inner.nostr.get_pending_nwc_invoices()?;

        if pending.is_empty() {
            return Ok(vec![]);
        }

        let profiles = self.inner.nostr.profiles();

        let pending: Vec<PendingNwcInvoice> = pending
            .into_iter()
            .flat_map(|inv| match inv.index {
                Some(index) => profiles
                    .iter()
                    .find(|p| p.index == index)
                    .map(|p| (inv, Some(p.name.clone())).into()),
                None => Some((inv, None).into()),
            })
            .collect();

        Ok(pending)
    }

    /// Approves an invoice and sends the payment
    pub async fn approve_invoice(&self, hash: String) -> Result<(), MutinyJsError> {
        self.inner
            .nostr
            .approve_invoice(hash.parse()?, &self.inner)
            .await?;

        Ok(())
    }

    /// Removes an invoice from the pending list, will also remove expired invoices
    pub async fn deny_invoice(&self, hash: String) -> Result<(), MutinyJsError> {
        let hash: sha256::Hash = hash
            .parse()
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        self.inner.nostr.deny_invoice(hash).await?;

        Ok(())
    }

    /// Removes all invoices from the pending list
    #[wasm_bindgen]
    pub async fn deny_all_pending_nwc(&self) -> Result<(), MutinyJsError> {
        self.inner.nostr.deny_all_pending_nwc().await?;

        Ok(())
    }

    /// Checks whether or not the user is subscribed to Mutiny+.
    /// Submits a NWC string to keep the subscription active if not expired.
    ///
    /// Returns None if there's no subscription at all.
    /// Returns Some(u64) for their unix expiration timestamp, which may be in the
    /// past or in the future, depending on whether or not it is currently active.
    #[wasm_bindgen]
    pub async fn check_subscribed(&self) -> Result<Option<u64>, MutinyJsError> {
        Ok(self.inner.check_subscribed().await?)
    }

    /// Gets the subscription plans for Mutiny+ subscriptions
    #[wasm_bindgen]
    pub async fn get_subscription_plans(&self) -> Result<JsValue /* Vec<Plan> */, MutinyJsError> {
        let plans = self.inner.get_subscription_plans().await?;

        Ok(JsValue::from_serde(&plans)?)
    }

    /// Subscribes to a Mutiny+ plan with a specific plan id.
    ///
    /// Returns a lightning invoice so that the plan can be paid for to start it.
    #[wasm_bindgen]
    pub async fn subscribe_to_plan(&self, id: u8) -> Result<MutinyInvoice, MutinyJsError> {
        Ok(self.inner.subscribe_to_plan(id).await?.into())
    }

    /// Pay the subscription invoice. This will post a NWC automatically afterwards.
    pub async fn pay_subscription_invoice(
        &self,
        invoice_str: String,
        autopay: bool,
    ) -> Result<(), MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice_str)?;
        self.inner
            .pay_subscription_invoice(&invoice, autopay)
            .await?;
        Ok(())
    }

    /// Returns the user's nostr profile data
    #[wasm_bindgen]
    pub fn get_nostr_profile(&self) -> Result<JsValue, MutinyJsError> {
        let profile = self.inner.nostr.get_profile()?;
        Ok(JsValue::from_serde(&profile)?)
    }

    /// This should only be called when the user is setting up a new profile
    /// never for an existing profile
    pub async fn setup_new_profile(
        &self,
        name: Option<String>,
        img_url: Option<String>,
        lnurl: Option<String>,
        nip05: Option<String>,
    ) -> Result<JsValue, MutinyJsError> {
        let img_url = img_url
            .map(|i| nostr::Url::from_str(&i))
            .transpose()
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;

        let lnurl = lnurl
            .map(|l| {
                LightningAddress::from_str(&l)
                    .map(|a| a.lnurl())
                    .or(LnUrl::from_str(&l))
            })
            .transpose()
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;

        let profile = self
            .inner
            .nostr
            .setup_new_profile(name, img_url, lnurl, nip05)
            .await?;
        Ok(JsValue::from_serde(&profile)?)
    }

    /// Sets the user's nostr profile data
    #[wasm_bindgen]
    pub async fn edit_nostr_profile(
        &self,
        name: Option<String>,
        img_url: Option<String>,
        lnurl: Option<String>,
        nip05: Option<String>,
    ) -> Result<JsValue, MutinyJsError> {
        let img_url = img_url
            .map(|i| nostr::Url::from_str(&i))
            .transpose()
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;

        let lnurl = lnurl
            .map(|l| {
                LightningAddress::from_str(&l)
                    .map(|a| a.lnurl())
                    .or(LnUrl::from_str(&l))
            })
            .transpose()
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;

        let profile = self
            .inner
            .nostr
            .edit_profile(name, img_url, lnurl, nip05)
            .await?;
        Ok(JsValue::from_serde(&profile)?)
    }

    /// Sets the user's nostr profile data to a "deleted" state
    #[wasm_bindgen]
    pub async fn delete_profile(&self) -> Result<JsValue, MutinyJsError> {
        let profile = self.inner.nostr.delete_profile().await?;
        Ok(JsValue::from_serde(&profile)?)
    }

    /// Syncs all of our nostr data from the configured primal instance
    pub async fn sync_nostr(&self) -> Result<(), MutinyJsError> {
        self.inner.sync_nostr().await?;
        Ok(())
    }

    /// Get contacts from the given npub and sync them to the wallet
    pub async fn sync_nostr_contacts(&self, npub_str: String) -> Result<(), MutinyJsError> {
        let npub = parse_npub_or_nip05(&npub_str).await?;
        self.inner.sync_nostr_contacts(npub).await?;
        Ok(())
    }

    /// Gets the list of npubs we're following
    pub async fn get_follow_list(
        &self,
    ) -> Result<JsValue /* Vec<nostr::PublicKey> */, MutinyJsError> {
        let list = self.inner.nostr.get_follow_list()?;
        let npubs: Vec<String> = list
            .into_iter()
            .map(|n| n.to_bech32().expect("bech32"))
            .collect();
        Ok(JsValue::from_serde(&npubs)?)
    }

    /// Follows the npub on nostr if we're not already following
    pub async fn follow_npub(&self, npub: String) -> Result<(), MutinyJsError> {
        let npub = parse_npub(&npub)?;
        Ok(self.inner.nostr.follow_npub(npub).await?)
    }

    /// Unfollows the npub on nostr if we're following them
    ///
    /// Returns true if we were following them before
    pub async fn unfollow_npub(&self, npub: String) -> Result<(), MutinyJsError> {
        let npub = parse_npub(&npub)?;
        Ok(self.inner.nostr.unfollow_npub(npub).await?)
    }

    /// Get dm conversation between us and given npub
    /// Returns a vector of messages sorted by newest first
    pub async fn get_dm_conversation(
        &self,
        npub: String,
        limit: u64,
        until: Option<u64>,
        since: Option<u64>,
    ) -> Result<JsValue /* Vec<DirectMessage> */, MutinyJsError> {
        let npub = parse_npub(&npub)?;
        let vec = self
            .inner
            .get_dm_conversation(npub, limit, until, since)
            .await?;

        let dms: Vec<DirectMessage> = vec.into_iter().map(|i| i.into()).collect();
        Ok(JsValue::from_serde(&dms)?)
    }

    /// Sends a DM to the given npub
    pub async fn send_dm(&self, npub: String, message: String) -> Result<String, MutinyJsError> {
        let npub = parse_npub(&npub)?;
        let event_id = self.inner.nostr.send_dm(npub, message).await?;
        Ok(event_id.to_hex())
    }

    /// Uploads a profile pic to nostr.build and returns the uploaded file's URL
    pub async fn upload_profile_pic(&self, img_base64: String) -> Result<String, MutinyJsError> {
        let bytes = base64::decode(&img_base64)?;
        Ok(self.inner.upload_profile_pic(bytes).await?)
    }

    /// Checks if a given LNURL name is available
    pub async fn check_available_lnurl_name(&self, name: String) -> Result<bool, MutinyJsError> {
        Ok(self.inner.check_available_lnurl_name(name).await?)
    }

    /// Reserves a given LNURL name for the user
    pub async fn reserve_lnurl_name(&self, name: String) -> Result<(), MutinyJsError> {
        Ok(self.inner.reserve_lnurl_name(name).await?)
    }

    /// Checks the registered username for the user
    pub async fn check_lnurl_name(&self) -> Result<Option<String>, MutinyJsError> {
        Ok(self.inner.check_lnurl_name().await?)
    }

    /// Resets the scorer and network graph. This can be useful if you get stuck in a bad state.
    #[wasm_bindgen]
    pub async fn reset_router(&self) -> Result<(), MutinyJsError> {
        self.inner.node_manager.reset_router().await?;
        // Sleep to wait for indexed db to finish writing
        sleep(500).await;
        Ok(())
    }

    /// Resets BDK's keychain tracker. This will require a re-sync of the blockchain.
    ///
    /// This can be useful if you get stuck in a bad state.
    #[wasm_bindgen]
    pub async fn reset_onchain_tracker(&mut self) -> Result<(), MutinyJsError> {
        Ok(self.inner.reset_onchain_tracker().await?)
    }

    /// Exports the current state of the node manager to a json object.
    #[wasm_bindgen]
    pub async fn export_json(password: Option<String>) -> Result<String, MutinyJsError> {
        let logger = Arc::new(MutinyLogger::default());
        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;
        // todo init vss
        let storage = IndexedDbStorage::new(password, cipher, None, logger).await?;
        if storage.get_mnemonic().is_err() {
            // if we get an error, then we have the wrong password
            return Err(MutinyJsError::IncorrectPassword);
        }
        let json = NodeManager::export_json(storage).await?;
        Ok(serde_json::to_string(&json)?)
    }

    /// Restore a node manager from a json object.
    #[wasm_bindgen]
    pub async fn import_json(json: String) -> Result<(), MutinyJsError> {
        let json: serde_json::Value = serde_json::from_str(&json)?;
        IndexedDbStorage::import(json).await?;
        Ok(())
    }

    /// Clears storage and deletes all data.
    ///
    /// All data in VSS persists but the device lock is cleared.
    #[wasm_bindgen]
    pub async fn delete_all(&self) -> Result<(), MutinyJsError> {
        self.inner.delete_all().await?;
        Ok(())
    }

    pub async fn resync_federation(&self, federation_id: String) -> Result<(), MutinyJsError> {
        let federation_id = FederationId::from_str(&federation_id)
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        self.inner.resync_federation(federation_id).await?;
        Ok(())
    }

    pub fn get_federation_resync_progress(
        &self,
        federation_id: String,
    ) -> Result<JsValue, MutinyJsError> {
        let federation_id = FederationId::from_str(&federation_id)
            .map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        let res = self.inner.get_federation_resync_progress(federation_id)?;
        Ok(JsValue::from_serde(&res)?)
    }

    /// Restore's the mnemonic after deleting the previous state.
    ///
    /// Backup the state beforehand. Does not restore lightning data.
    /// Should refresh or restart afterwards. Wallet should be stopped.
    #[wasm_bindgen]
    pub async fn restore_mnemonic(
        m: String,
        password: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let logger = Arc::new(MutinyLogger::default());
        let cipher = password
            .as_ref()
            .filter(|p| !p.is_empty())
            .map(|p| encryption_key_from_pass(p))
            .transpose()?;
        let storage = IndexedDbStorage::new(password, cipher, None, logger.clone()).await?;
        mutiny_core::MutinyWallet::<IndexedDbStorage>::restore_mnemonic(
            storage,
            Mnemonic::from_str(&m).map_err(|_| MutinyJsError::InvalidMnemonic)?,
        )
        .await?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn change_password(
        &mut self,
        old_password: Option<String>,
        new_password: Option<String>,
    ) -> Result<(), MutinyJsError> {
        let old_p = old_password.filter(|p| !p.is_empty());
        let new_p = new_password.filter(|p| !p.is_empty());
        self.inner.change_password(old_p, new_p).await?;
        Ok(())
    }

    /// Converts a bitcoin amount in BTC to satoshis.
    #[wasm_bindgen]
    pub fn convert_btc_to_sats(btc: f64) -> Result<u64, MutinyJsError> {
        // rust bitcoin doesn't like extra precision in the float
        // so we round to the nearest satoshi
        // explained here: https://stackoverflow.com/questions/28655362/how-does-one-round-a-floating-point-number-to-a-specified-number-of-digits
        let truncated = 10i32.pow(8) as f64;
        let btc = (btc * truncated).round() / truncated;
        if let Ok(amount) = bitcoin::Amount::from_btc(btc) {
            Ok(amount.to_sat())
        } else {
            Err(MutinyJsError::BadAmountError)
        }
    }

    /// Converts a satoshi amount to BTC.
    #[wasm_bindgen]
    pub fn convert_sats_to_btc(sats: u64) -> f64 {
        bitcoin::Amount::from_sat(sats).to_btc()
    }

    /// Convert an npub string to a hex string
    #[wasm_bindgen]
    pub async fn nsec_to_npub(nsec: String) -> Result<String, MutinyJsError> {
        let nsec = Keys::parse(nsec).map_err(|_| MutinyJsError::InvalidArgumentsError)?;
        Ok(nsec.public_key().to_bech32().expect("bech32"))
    }

    /// Convert an npub string to a hex string
    #[wasm_bindgen]
    pub async fn npub_to_hexpub(npub: String) -> Result<String, MutinyJsError> {
        let npub = parse_npub_or_nip05(&npub).await?;
        Ok(npub.serialize().to_lower_hex_string())
    }

    /// Convert an hex string to a npub string
    #[wasm_bindgen]
    pub async fn hexpub_to_npub(npub: String) -> Result<String, MutinyJsError> {
        let npub = parse_npub_or_nip05(&npub).await?;
        Ok(npub.to_bech32().expect("bech32"))
    }

    /// If the invoice is from a node that gives hodl invoices
    #[wasm_bindgen]
    pub async fn is_potential_hodl_invoice(invoice: String) -> Result<bool, MutinyJsError> {
        let invoice = Bolt11Invoice::from_str(&invoice)?;
        Ok(mutiny_core::utils::is_hodl_invoice(&invoice))
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::test::*;
    use crate::{uninit, MutinyWallet};

    use crate::error::MutinyJsError;
    use crate::indexed_db::IndexedDbStorage;
    use js_sys::Array;
    use mutiny_core::storage::MutinyStorage;
    use mutiny_core::utils::sleep;
    use wasm_bindgen::JsCast;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        log!("creating mutiny wallet!");
        let password = Some("password".to_string());

        assert!(!MutinyWallet::has_node_manager().await.unwrap());
        MutinyWallet::new(
            password.clone(),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        sleep(1_000).await;
        assert!(MutinyWallet::has_node_manager().await.unwrap());

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn fail_to_create_wallet_different_seed() {
        MutinyWallet::new(
            None,
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        sleep(1_000).await;
        assert!(MutinyWallet::has_node_manager().await.unwrap());
        uninit().await;

        let seed = mutiny_core::generate_seed(12).unwrap();
        let result = MutinyWallet::new(
            None,
            Some(seed.to_string()),
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;

        match result {
            Err(MutinyJsError::InvalidMnemonic) => {}
            Err(e) => panic!("should have failed to create wallet with different seed {e:?}"),
            Ok(_) => panic!("should have failed to create wallet with different seed"),
        }

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn fail_to_create_2_mutiny_wallets() {
        log!("trying to create 2 mutiny wallets!");
        let password = Some("password".to_string());

        assert!(!MutinyWallet::has_node_manager().await.unwrap());
        MutinyWallet::new(
            password.clone(),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");
        sleep(1_000).await;
        assert!(MutinyWallet::has_node_manager().await.unwrap());

        // try to create a second
        let result = MutinyWallet::new(
            password.clone(),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;

        if let Err(MutinyJsError::AlreadyRunning) = result {
            // this is the expected error
        } else {
            panic!("should have failed to create a second mutiny wallet");
        };

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn correctly_show_seed() {
        log!("showing seed");

        let seed = mutiny_core::generate_seed(12).unwrap();

        let password = Some("password".to_string());

        // make sure storage is empty
        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");

        let nm = MutinyWallet::new(
            password.clone(),
            Some(seed.to_string()),
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        log!("checking nm");
        assert!(MutinyWallet::has_node_manager().await.unwrap());
        log!("checking seed");
        assert_eq!(seed.to_string(), nm.show_seed());

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn give_correct_err_with_wrong_password() {
        let seed = mutiny_core::generate_seed(12).unwrap();

        let password = Some("password".to_string());

        // make sure storage is empty
        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");

        let nm = MutinyWallet::new(
            password.clone(),
            Some(seed.to_string()),
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        log!("checking nm");
        assert!(MutinyWallet::has_node_manager().await.unwrap());
        log!("checking seed");
        assert_eq!(seed.to_string(), nm.show_seed());
        nm.stop().await.unwrap();
        drop(nm);
        uninit().await;

        // create with incorrect password
        let result = MutinyWallet::new(
            None,
            Some(seed.to_string()),
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await;

        if !matches!(result, Err(MutinyJsError::IncorrectPassword)) {
            panic!("should have failed to create wallet with incorrect password");
        }

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn created_new_nodes() {
        log!("creating new nodes");

        let nm = MutinyWallet::new(
            Some("password".to_string()),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");

        let node_identity = nm.new_node().await.expect("should create new node");
        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        let node_identity = nm
            .new_node()
            .await
            .expect("mutiny wallet should initialize");

        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    fn js_to_option_vec_string(js_val: JsValue) -> Result<Option<Vec<String>>, JsValue> {
        if js_val.is_undefined() || js_val.is_null() {
            return Ok(None);
        }

        let js_array: Array = js_val
            .dyn_into()
            .map_err(|_| JsValue::from_str("Expected an array"))?;

        let vec_string: Result<Vec<String>, _> = (0..js_array.length())
            .map(|index| {
                js_array
                    .get(index)
                    .as_string()
                    .ok_or_else(|| JsValue::from_str("Expected an array of strings"))
            })
            .collect();

        vec_string.map(Some)
    }

    #[test]
    async fn test_get_logs_no_password() {
        log!("getting logs with no password");

        let nm = MutinyWallet::new(
            None,
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");

        // create the nodes so we have some extra data
        let node_identity = nm.new_node().await.expect("should create new node");
        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        let node_identity = nm
            .new_node()
            .await
            .expect("mutiny wallet should initialize");

        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        // sleep to make sure logs save
        sleep(6_000).await;
        let logs = MutinyWallet::get_logs().await.expect("should get logs");
        let parsed_logs = js_to_option_vec_string(logs).expect("should parse logs");
        assert!(parsed_logs.is_some());
        assert!(!parsed_logs.clone().unwrap().is_empty());
        assert_ne!("", parsed_logs.unwrap()[0]);

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }

    #[test]
    async fn test_get_logs_with_password() {
        log!("getting logs with password");

        let password = Some("password".to_string());
        let nm = MutinyWallet::new(
            password.clone(),
            None,
            None,
            Some("regtest".to_owned()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("mutiny wallet should initialize");

        // create the nodes so we have some extra data
        let node_identity = nm.new_node().await.expect("should create new node");
        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        let node_identity = nm
            .new_node()
            .await
            .expect("mutiny wallet should initialize");

        assert_ne!("", node_identity.uuid());
        assert_ne!("", node_identity.pubkey());

        // sleep to make sure logs save
        sleep(6_000).await;
        let logs = MutinyWallet::get_logs().await.expect("should get logs");
        let parsed_logs = js_to_option_vec_string(logs).expect("should parse logs");
        assert!(parsed_logs.is_some());
        assert!(!parsed_logs.clone().unwrap().is_empty());
        assert_ne!("", parsed_logs.unwrap()[0]);

        IndexedDbStorage::clear()
            .await
            .expect("failed to clear storage");
        uninit().await;
    }
}
