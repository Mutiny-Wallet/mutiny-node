#![crate_name = "mutiny_core"]
// wasm is considered "extra_unused_type_parameters"
#![allow(
    async_fn_in_trait,
    incomplete_features,
    clippy::extra_unused_type_parameters,
    clippy::arc_with_non_send_sync,
    type_alias_bounds
)]
extern crate core;

pub mod auth;
mod chain;
mod dlc;
pub mod encrypt;
pub mod error;
pub mod event;
pub mod federation;
mod fees;
mod gossip;
mod key;
mod keymanager;
pub mod labels;
mod ldkstorage;
pub mod lnurlauth;
pub mod logging;
mod lsp;
mod messagehandler;
mod networking;
mod node;
pub mod nodemanager;
pub mod nostr;
mod onchain;
mod peermanager;
pub mod scorer;
pub mod storage;
mod subscription;
pub mod utils;
pub mod vss;

#[cfg(test)]
mod test_utils;

use crate::dlc::DlcHandler;
pub use crate::dlc::{DLC_CONTRACT_KEY_PREFIX, DLC_KEY_INDEX_KEY};
use crate::event::{HTLCStatus, MillisatAmount, PaymentInfo};
pub use crate::gossip::{GOSSIP_SYNC_TIME_KEY, NETWORK_GRAPH_KEY, PROB_SCORER_KEY};
pub use crate::keymanager::generate_seed;
use crate::labels::LabelItem;
pub use crate::ldkstorage::{CHANNEL_MANAGER_KEY, MONITORS_PREFIX_KEY};
use crate::nostr::dlc::DlcMessageType;
use crate::storage::{
    list_payment_info, MutinyStorage, DEVICE_ID_KEY, EXPECTED_NETWORK_KEY, NEED_FULL_SYNC_KEY,
};
use crate::utils::parse_profile_metadata;
use crate::{auth::MutinyAuthClient, logging::MutinyLogger};
use crate::{error::MutinyError, nostr::ReservedProfile};
use crate::{
    federation::{FederationClient, FederationIdentity, FederationIndex, FederationStorage},
    labels::{get_contact_key, Contact, LabelStorage},
    nodemanager::NodeBalance,
};
use crate::{
    lnurlauth::make_lnurl_auth_connection,
    nodemanager::{ChannelClosure, MutinyBip21RawMaterials, TransactionDetails},
};
use crate::{lnurlauth::AuthManager, nostr::MUTINY_PLUS_SUBSCRIPTION_LABEL};
use crate::{logging::LOGGING_KEY, nodemanager::NodeManagerBuilder};
use crate::{nodemanager::NodeManager, nostr::ProfileType};
use crate::{
    nostr::nwc::{BudgetPeriod, BudgetedSpendingConditions, NwcProfileTag, SpendingConditions},
    subscription::MutinySubscriptionClient,
};
use crate::{nostr::NostrManager, utils::sleep};
pub use ::dlc as rust_dlc;
pub use ::dlc_manager;
pub use ::dlc_messages;
use ::nostr::key::XOnlyPublicKey;
use ::nostr::nips::nip57;
use ::nostr::prelude::ZapRequestData;
use ::nostr::secp256k1::Parity;
use ::nostr::{JsonUtil, Kind};
use async_lock::RwLock;
use bdk_chain::ConfirmationTime;
use bip39::Mnemonic;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use dlc_manager::contract::contract_input::{ContractInput, ContractInputInfo, OracleInput};
use dlc_manager::contract::enum_descriptor::EnumDescriptor;
use dlc_manager::contract::{Contract, ContractDescriptor};
use dlc_manager::{ContractId, Storage};
use dlc_messages::oracle_msgs::EventDescriptor;
pub use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::Message;
use esplora_client::OutputStatus;
use fedimint_core::{api::InviteCode, config::FederationId};
use futures::{pin_mut, select, FutureExt};
use lightning::ln::PaymentHash;
use lightning::{log_debug, util::logger::Logger};
use lightning::{log_error, log_info, log_warn};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription};
use lnurl::{lnurl::LnUrl, AsyncClient as LnUrlClient, LnUrlResponse, Response};
use nostr_sdk::{Client, RelayPoolNotification};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::{collections::HashMap, sync::atomic::AtomicBool};
use std::{str::FromStr, sync::atomic::Ordering};
use uuid::Uuid;

#[cfg(test)]
use mockall::{automock, predicate::*};

const DEFAULT_PAYMENT_TIMEOUT: u64 = 30;

#[cfg_attr(test, automock)]
pub trait InvoiceHandler {
    fn logger(&self) -> &MutinyLogger;
    fn skip_hodl_invoices(&self) -> bool;
    async fn get_outbound_payment_status(&self, payment_hash: &[u8; 32]) -> Option<HTLCStatus>;
    async fn pay_invoice(
        &self,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError>;
    async fn create_invoice(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError>;
}

pub struct LnUrlParams {
    pub max: u64,
    pub min: u64,
    pub tag: String,
}

/// Plan is a subscription plan for Mutiny+
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Plan {
    /// The ID of the internal plan.
    /// Used for subscribing to specific one.
    pub id: u8,

    /// The amount in sats for the plan.
    pub amount_sat: u64,
}

#[derive(Copy, Clone)]
pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
    pub federation: u64,
    pub force_close: u64,
}

impl MutinyBalance {
    fn new(ln_balance: NodeBalance, federation_balance: u64) -> Self {
        Self {
            confirmed: ln_balance.confirmed,
            unconfirmed: ln_balance.unconfirmed,
            lightning: ln_balance.lightning,
            federation: federation_balance,
            force_close: ln_balance.force_close,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FederationBalance {
    pub identity: FederationIdentity,
    pub balance: u64,
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct FederationBalances {
    pub balances: Vec<FederationBalance>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ActivityItem {
    OnChain(TransactionDetails),
    Lightning(Box<MutinyInvoice>),
    ChannelClosed(ChannelClosure),
}

impl ActivityItem {
    pub fn last_updated(&self) -> Option<u64> {
        match self {
            ActivityItem::OnChain(t) => match t.confirmation_time {
                ConfirmationTime::Confirmed { time, .. } => Some(time),
                ConfirmationTime::Unconfirmed { .. } => None,
            },
            ActivityItem::Lightning(i) => match i.status {
                HTLCStatus::Succeeded => Some(i.last_updated),
                HTLCStatus::Failed => Some(i.last_updated),
                HTLCStatus::Pending | HTLCStatus::InFlight => None,
            },
            ActivityItem::ChannelClosed(c) => Some(c.timestamp),
        }
    }

    pub fn labels(&self) -> Vec<String> {
        match self {
            ActivityItem::OnChain(t) => t.labels.clone(),
            ActivityItem::Lightning(i) => i.labels.clone(),
            ActivityItem::ChannelClosed(_) => vec![],
        }
    }

    pub fn is_channel_open(&self) -> bool {
        match self {
            ActivityItem::OnChain(onchain) => {
                onchain.labels.iter().any(|l| l.contains("LN Channel:"))
            }
            ActivityItem::Lightning(_) => false,
            ActivityItem::ChannelClosed(_) => false,
        }
    }
}

impl PartialOrd for ActivityItem {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActivityItem {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // We want None to be greater than Some because those are pending transactions
        // so those should be at the top of the list
        let sort = match (self.last_updated(), other.last_updated()) {
            (Some(self_time), Some(other_time)) => self_time.cmp(&other_time),
            (Some(_), None) => core::cmp::Ordering::Less,
            (None, Some(_)) => core::cmp::Ordering::Greater,
            (None, None) => {
                // if both are none, do lightning first
                match (self, other) {
                    (ActivityItem::Lightning(_), ActivityItem::OnChain(_)) => {
                        core::cmp::Ordering::Greater
                    }
                    (ActivityItem::OnChain(_), ActivityItem::Lightning(_)) => {
                        core::cmp::Ordering::Less
                    }
                    (ActivityItem::Lightning(l1), ActivityItem::Lightning(l2)) => {
                        // compare lightning by expire time
                        l1.expire.cmp(&l2.expire)
                    }
                    (ActivityItem::OnChain(o1), ActivityItem::OnChain(o2)) => {
                        // compare onchain by confirmation time (which will be last seen for unconfirmed)
                        o1.confirmation_time.cmp(&o2.confirmation_time)
                    }
                    _ => core::cmp::Ordering::Equal,
                }
            }
        };

        // if the sort is equal, sort by serialization so we have a stable sort
        sort.then_with(|| {
            serde_json::to_string(self)
                .unwrap()
                .cmp(&serde_json::to_string(other).unwrap())
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MutinyInvoice {
    pub bolt11: Option<Bolt11Invoice>,
    pub description: Option<String>,
    pub payment_hash: sha256::Hash,
    pub preimage: Option<String>,
    pub payee_pubkey: Option<PublicKey>,
    pub amount_sats: Option<u64>,
    pub expire: u64,
    pub status: HTLCStatus,
    pub fees_paid: Option<u64>,
    pub inbound: bool,
    pub labels: Vec<String>,
    pub last_updated: u64,
}

impl MutinyInvoice {
    pub fn paid(&self) -> bool {
        self.status == HTLCStatus::Succeeded
    }
}

impl From<Bolt11Invoice> for MutinyInvoice {
    fn from(value: Bolt11Invoice) -> Self {
        let description = match value.description() {
            Bolt11InvoiceDescription::Direct(a) => {
                if a.is_empty() {
                    None
                } else {
                    Some(a.to_string())
                }
            }
            Bolt11InvoiceDescription::Hash(_) => None,
        };

        let timestamp = value.duration_since_epoch().as_secs();
        let expiry = timestamp + value.expiry_time().as_secs();

        let payment_hash = value.payment_hash().to_owned();
        let payee_pubkey = value.payee_pub_key().map(|p| p.to_owned());
        let amount_sats = value.amount_milli_satoshis().map(|m| m / 1000);

        MutinyInvoice {
            bolt11: Some(value),
            description,
            payment_hash,
            preimage: None,
            payee_pubkey,
            amount_sats,
            expire: expiry,
            status: HTLCStatus::Pending,
            fees_paid: None,
            inbound: true,
            labels: vec![],
            last_updated: timestamp,
        }
    }
}

impl From<MutinyInvoice> for PaymentInfo {
    fn from(invoice: MutinyInvoice) -> Self {
        let preimage = invoice
            .preimage
            .map(|s| hex::decode(s).expect("preimage should decode"))
            .map(|v| {
                let mut arr = [0; 32];
                arr[..].copy_from_slice(&v);
                arr
            });
        let secret = None;
        let status = invoice.status;
        let amt_msat = invoice
            .amount_sats
            .map(|s| MillisatAmount(Some(s)))
            .unwrap_or(MillisatAmount(None));
        let fee_paid_msat = invoice.fees_paid.map(|f| f * 1_000);
        let bolt11 = invoice.bolt11;
        let payee_pubkey = invoice.payee_pubkey;
        let last_update = invoice.last_updated;

        PaymentInfo {
            preimage,
            secret,
            status,
            amt_msat,
            fee_paid_msat,
            bolt11,
            payee_pubkey,
            last_update,
        }
    }
}

impl MutinyInvoice {
    pub(crate) fn from(
        i: PaymentInfo,
        payment_hash: PaymentHash,
        inbound: bool,
        labels: Vec<String>,
    ) -> Result<Self, MutinyError> {
        match i.bolt11 {
            Some(invoice) => {
                // Construct an invoice from a bolt11, easy
                let amount_sats = if let Some(inv_amt) = invoice.amount_milli_satoshis() {
                    if inv_amt == 0 {
                        i.amt_msat.0.map(|a| a / 1_000)
                    } else {
                        Some(inv_amt / 1_000)
                    }
                } else {
                    i.amt_msat.0.map(|a| a / 1_000)
                };
                Ok(MutinyInvoice {
                    inbound,
                    last_updated: i.last_update,
                    status: i.status,
                    labels,
                    amount_sats,
                    payee_pubkey: i.payee_pubkey,
                    preimage: i.preimage.map(|p| p.to_hex()),
                    fees_paid: i.fee_paid_msat.map(|f| f / 1_000),
                    ..invoice.into()
                })
            }
            None => {
                let amount_sats: Option<u64> = i.amt_msat.0.map(|s| s / 1_000);
                let fees_paid = i.fee_paid_msat.map(|f| f / 1_000);
                let preimage = i.preimage.map(|p| p.to_hex());
                let payment_hash = sha256::Hash::from_inner(payment_hash.0);
                let invoice = MutinyInvoice {
                    bolt11: None,
                    description: None,
                    payment_hash,
                    preimage,
                    payee_pubkey: i.payee_pubkey,
                    amount_sats,
                    expire: i.last_update,
                    status: i.status,
                    fees_paid,
                    inbound,
                    labels,
                    last_updated: i.last_update,
                };
                Ok(invoice)
            }
        }
    }
}

pub struct MutinyWalletConfigBuilder {
    xprivkey: ExtendedPrivKey,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: Option<String>,
    network: Option<Network>,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
    lsp_connection_string: Option<String>,
    lsp_token: Option<String>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    subscription_url: Option<String>,
    scorer_url: Option<String>,
    do_not_connect_peers: bool,
    skip_device_lock: bool,
    pub safe_mode: bool,
    skip_hodl_invoices: bool,
}

impl MutinyWalletConfigBuilder {
    pub fn new(xprivkey: ExtendedPrivKey) -> MutinyWalletConfigBuilder {
        MutinyWalletConfigBuilder {
            xprivkey,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr: None,
            network: None,
            user_esplora_url: None,
            user_rgs_url: None,
            lsp_url: None,
            lsp_connection_string: None,
            lsp_token: None,
            auth_client: None,
            subscription_url: None,
            scorer_url: None,
            do_not_connect_peers: false,
            skip_device_lock: false,
            safe_mode: false,
            skip_hodl_invoices: true,
        }
    }

    /// Required
    pub fn with_network(mut self, network: Network) -> MutinyWalletConfigBuilder {
        self.network = Some(network);
        self
    }

    #[cfg(target_arch = "wasm32")]
    pub fn with_websocket_proxy_addr(&mut self, websocket_proxy_addr: String) {
        self.websocket_proxy_addr = Some(websocket_proxy_addr);
    }

    pub fn with_user_esplora_url(&mut self, user_esplora_url: String) {
        self.user_esplora_url = Some(user_esplora_url);
    }

    pub fn with_user_rgs_url(&mut self, user_rgs_url: String) {
        self.user_rgs_url = Some(user_rgs_url);
    }

    pub fn with_lsp_url(&mut self, lsp_url: String) {
        self.lsp_url = Some(lsp_url);
    }

    pub fn with_lsp_connection_string(&mut self, lsp_connection_string: String) {
        self.lsp_connection_string = Some(lsp_connection_string);
    }

    pub fn with_lsp_token(&mut self, lsp_token: String) {
        self.lsp_token = Some(lsp_token);
    }

    pub fn with_auth_client(&mut self, auth_client: Arc<MutinyAuthClient>) {
        self.auth_client = Some(auth_client);
    }

    pub fn with_subscription_url(&mut self, subscription_url: String) {
        self.subscription_url = Some(subscription_url);
    }

    pub fn with_scorer_url(&mut self, scorer_url: String) {
        self.scorer_url = Some(scorer_url);
    }

    pub fn do_not_connect_peers(&mut self) {
        self.do_not_connect_peers = true;
    }

    pub fn with_skip_device_lock(&mut self) {
        self.skip_device_lock = true;
    }

    pub fn with_safe_mode(&mut self) {
        self.safe_mode = true;
        self.skip_device_lock = true;
    }

    pub fn do_not_skip_hodl_invoices(&mut self) {
        self.skip_hodl_invoices = false;
    }

    pub fn build(self) -> MutinyWalletConfig {
        let network = self.network.expect("network is required");

        MutinyWalletConfig {
            xprivkey: self.xprivkey,
            #[cfg(target_arch = "wasm32")]
            websocket_proxy_addr: self.websocket_proxy_addr,
            network,
            user_esplora_url: self.user_esplora_url,
            user_rgs_url: self.user_rgs_url,
            lsp_url: self.lsp_url,
            lsp_connection_string: self.lsp_connection_string,
            lsp_token: self.lsp_token,
            auth_client: self.auth_client,
            subscription_url: self.subscription_url,
            scorer_url: self.scorer_url,
            do_not_connect_peers: self.do_not_connect_peers,
            skip_device_lock: self.skip_device_lock,
            safe_mode: self.safe_mode,
            skip_hodl_invoices: self.skip_hodl_invoices,
        }
    }
}

pub fn create_contract_input(
    collateral: u64,
    descriptor: EnumDescriptor,
    announcement: OracleAnnouncement,
    fee_rate: u64,
) -> Result<ContractInput, MutinyError> {
    match announcement.oracle_event.event_descriptor {
        EventDescriptor::EnumEvent(e) => {
            if e.outcomes
                != descriptor
                    .outcome_payouts
                    .iter()
                    .map(|x| x.outcome.clone())
                    .collect::<Vec<_>>()
            {
                return Err(MutinyError::InvalidArgumentsError);
            }
        }
        EventDescriptor::DigitDecompositionEvent(_) => unimplemented!("digit decomposition"),
    }
    let contract_info = ContractInputInfo {
        contract_descriptor: ContractDescriptor::Enum(descriptor),
        oracles: OracleInput {
            public_keys: vec![announcement.oracle_public_key],
            event_id: announcement.oracle_event.event_id,
            threshold: 1,
        },
    };

    let input = ContractInput {
        offer_collateral: collateral,
        accept_collateral: collateral,
        fee_rate,
        contract_infos: vec![contract_info],
    };

    input.validate().map_err(|e| {
        log::error!("Error validating contract input: {e}");
        MutinyError::DLCManagerError
    })?;

    Ok(input)
}

#[derive(Clone)]
pub struct MutinyWalletConfig {
    xprivkey: ExtendedPrivKey,
    #[cfg(target_arch = "wasm32")]
    websocket_proxy_addr: Option<String>,
    network: Network,
    user_esplora_url: Option<String>,
    user_rgs_url: Option<String>,
    lsp_url: Option<String>,
    lsp_connection_string: Option<String>,
    lsp_token: Option<String>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    subscription_url: Option<String>,
    scorer_url: Option<String>,
    do_not_connect_peers: bool,
    skip_device_lock: bool,
    pub safe_mode: bool,
    skip_hodl_invoices: bool,
}

pub struct MutinyWalletBuilder<S: MutinyStorage> {
    xprivkey: ExtendedPrivKey,
    storage: S,
    config: Option<MutinyWalletConfig>,
    session_id: Option<String>,
    network: Option<Network>,
    auth_client: Option<Arc<MutinyAuthClient>>,
    subscription_url: Option<String>,
    do_not_connect_peers: bool,
    skip_hodl_invoices: bool,
    skip_device_lock: bool,
    safe_mode: bool,
}

impl<S: MutinyStorage> MutinyWalletBuilder<S> {
    pub fn new(xprivkey: ExtendedPrivKey, storage: S) -> MutinyWalletBuilder<S> {
        MutinyWalletBuilder::<S> {
            xprivkey,
            storage,
            config: None,
            session_id: None,
            network: None,
            auth_client: None,
            subscription_url: None,
            do_not_connect_peers: false,
            skip_device_lock: false,
            safe_mode: false,
            skip_hodl_invoices: true,
        }
    }

    pub fn with_config(mut self, config: MutinyWalletConfig) -> MutinyWalletBuilder<S> {
        self.network = Some(config.network);
        self.do_not_connect_peers = config.do_not_connect_peers;
        self.skip_hodl_invoices = config.skip_hodl_invoices;
        self.skip_device_lock = config.skip_device_lock;
        self.safe_mode = config.safe_mode;
        self.auth_client = config.auth_client.clone();
        self.subscription_url = config.subscription_url.clone();
        self.config = Some(config);
        self
    }

    pub fn with_session_id(&mut self, session_id: String) {
        self.session_id = Some(session_id);
    }

    pub fn with_network(&mut self, network: Network) {
        self.network = Some(network);
    }

    pub fn with_auth_client(&mut self, auth_client: Arc<MutinyAuthClient>) {
        self.auth_client = Some(auth_client);
    }

    pub fn with_subscription_url(&mut self, subscription_url: String) {
        self.subscription_url = Some(subscription_url);
    }

    pub fn do_not_connect_peers(&mut self) {
        self.do_not_connect_peers = true;
    }

    pub fn do_not_skip_hodl_invoices(&mut self) {
        self.skip_hodl_invoices = false;
    }

    pub fn with_skip_device_lock(&mut self) {
        self.skip_device_lock = true;
    }

    pub fn with_safe_mode(&mut self) {
        self.safe_mode = true;
        self.skip_device_lock = true;
    }

    pub async fn build(self) -> Result<MutinyWallet<S>, MutinyError> {
        let network = self
            .network
            .map_or_else(|| Err(MutinyError::InvalidArgumentsError), Ok)?;
        let config = self.config.unwrap_or(
            MutinyWalletConfigBuilder::new(self.xprivkey)
                .with_network(network)
                .build(),
        );

        let expected_network = self.storage.get::<Network>(EXPECTED_NETWORK_KEY)?;
        match expected_network {
            Some(n) => {
                if n != network {
                    return Err(MutinyError::NetworkMismatch);
                }
            }
            None => self
                .storage
                .set_data(EXPECTED_NETWORK_KEY.to_string(), self.network, None)?,
        }

        let stop = Arc::new(AtomicBool::new(false));
        let logger = Arc::new(MutinyLogger::with_writer(
            stop.clone(),
            self.storage.clone(),
            self.session_id,
        ));

        let mut nm_builder = NodeManagerBuilder::new(self.xprivkey, self.storage.clone())
            .with_config(config.clone());
        nm_builder.with_stop(stop.clone());
        nm_builder.with_logger(logger.clone());
        let node_manager = Arc::new(nm_builder.build().await?);

        let dlc = Arc::new(DlcHandler::new(
            node_manager.wallet.clone(),
            node_manager.logger.clone(),
        )?);

        NodeManager::start_sync(node_manager.clone());

        // DLC syncing
        let esplora = node_manager.esplora.clone();
        let dlc_clone = dlc.clone();
        let dlc_stop = node_manager.stop.clone();
        utils::spawn(async move {
            loop {
                if dlc_stop.load(Ordering::Relaxed) {
                    break;
                };

                let mut dlc = dlc_clone.manager.lock().await;
                if let Err(e) = dlc.periodic_check(false) {
                    log_error!(dlc_clone.logger, "Error checking DLCs: {e:?}");
                } else {
                    log_info!(dlc_clone.logger, "DLCs synced!");
                }
                drop(dlc);

                // check if any of the contracts have been closed
                let to_watch = dlc_clone.outputs_to_watch().unwrap_or_default();
                for (outpoint, contract) in to_watch {
                    // if it has been spent, find the close tx and process it
                    if let Ok(Some(OutputStatus {
                        txid: Some(txid), ..
                    })) = esplora
                        .get_output_status(&outpoint.txid, outpoint.vout as u64)
                        .await
                    {
                        if let Ok(Some(tx)) = esplora.get_tx(&txid).await {
                            let mut dlc = dlc_clone.manager.lock().await;
                            // for now just put 6 confirmations
                            if let Err(e) = dlc.on_counterparty_close(&contract, tx, 6) {
                                log_error!(dlc_clone.logger, "Error processing close tx: {e:?}");
                            }
                        }
                    }
                }

                sleep(60_000).await;
            }
        });

        // create nostr manager
        let nostr = Arc::new(NostrManager::from_mnemonic(
            self.xprivkey,
            dlc.clone(),
            self.storage.clone(),
            logger.clone(),
            stop.clone(),
        )?);

        // create federation module if any exist
        let federation_storage = self.storage.get_federations()?;
        let federations = if !federation_storage.federations.is_empty() {
            create_federations(federation_storage.clone(), &config, &self.storage, &logger).await?
        } else {
            Arc::new(RwLock::new(HashMap::new()))
        };

        if !self.skip_hodl_invoices {
            log_warn!(
                logger,
                "Starting with HODL invoices enabled. This is not recommended!"
            );
        }

        let lnurl_client = Arc::new(
            lnurl::Builder::default()
                .build_async()
                .expect("failed to make lnurl client"),
        );

        let (subscription_client, auth) = if let Some(auth_client) = self.auth_client.clone() {
            if let Some(subscription_url) = self.subscription_url {
                let auth = auth_client.auth.clone();
                let s = Arc::new(MutinySubscriptionClient::new(
                    auth_client,
                    subscription_url,
                    logger.clone(),
                ));
                (Some(s), auth)
            } else {
                (None, auth_client.auth.clone())
            }
        } else {
            let auth_manager = AuthManager::new(self.xprivkey)?;
            (None, auth_manager)
        };

        let mw = MutinyWallet {
            xprivkey: self.xprivkey,
            config,
            storage: self.storage,
            node_manager,
            nostr,
            federation_storage: Arc::new(RwLock::new(federation_storage)),
            federations,
            lnurl_client,
            subscription_client,
            auth,
            dlc,
            stop,
            logger,
            network,
            skip_hodl_invoices: self.skip_hodl_invoices,
            safe_mode: self.safe_mode,
        };

        #[cfg(not(test))]
        {
            // if we need a full sync from a restore
            if mw.storage.get(NEED_FULL_SYNC_KEY)?.unwrap_or_default() {
                mw.node_manager.wallet.full_sync().await?;
                mw.storage.delete(&[NEED_FULL_SYNC_KEY])?;
            }
        }

        // if we are in safe mode, don't create any nodes or
        // start any nostr services
        if self.safe_mode {
            return Ok(mw);
        }

        // if we don't have any nodes, create one
        match mw.node_manager.list_nodes().await?.pop() {
            Some(_) => (),
            None => {
                mw.node_manager.new_node().await?;
            }
        };

        // start the nostr wallet connect background process
        mw.start_nostr().await;

        // start the federation background processor
        mw.start_fedimint_background_checker().await;

        Ok(mw)
    }
}

/// MutinyWallet is the main entry point for the library.
/// It contains the NodeManager, which is the main interface to manage the
/// bitcoin and the lightning functionality.
#[derive(Clone)]
pub struct MutinyWallet<S: MutinyStorage> {
    xprivkey: ExtendedPrivKey,
    config: MutinyWalletConfig,
    pub(crate) storage: S,
    pub node_manager: Arc<NodeManager<S>>,
    pub nostr: Arc<NostrManager<S>>,
    pub federation_storage: Arc<RwLock<FederationStorage>>,
    pub(crate) federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    lnurl_client: Arc<LnUrlClient>,
    auth: AuthManager,
    subscription_client: Option<Arc<MutinySubscriptionClient>>,
    pub dlc: Arc<DlcHandler<S>>,
    pub stop: Arc<AtomicBool>,
    pub logger: Arc<MutinyLogger>,
    network: Network,
    skip_hodl_invoices: bool,
    safe_mode: bool,
}

impl<S: MutinyStorage> MutinyWallet<S> {
    /// Starts up all the nodes again.
    /// Not needed after [NodeManager]'s `new()` function.
    pub async fn start(&mut self) -> Result<(), MutinyError> {
        self.storage.start().await?;

        let mut nm_builder = NodeManagerBuilder::new(self.xprivkey, self.storage.clone())
            .with_config(self.config.clone());
        nm_builder.with_stop(self.stop.clone());
        nm_builder.with_logger(self.logger.clone());

        // when we restart, gen a new session id
        self.node_manager = Arc::new(nm_builder.build().await?);
        NodeManager::start_sync(self.node_manager.clone());

        Ok(())
    }

    /// Sends a DLC offer to the given pubkey over Nostr.
    pub async fn send_dlc_offer(
        &self,
        contract_input: &ContractInput,
        oracle_announcement: OracleAnnouncement,
        pubkey: XOnlyPublicKey,
    ) -> Result<ContractId, MutinyError> {
        // make sure we aren't sending an offer to ourselves
        if pubkey == self.nostr.dlc_handler.public_key() {
            return Err(MutinyError::InvalidArgumentsError);
        }

        let mut dlc = self.dlc.manager.lock().await;
        let counter_party = PublicKey::from_slice(&pubkey.public_key(Parity::Even).serialize())
            .expect("converting pubkey between crates should not fail");
        let msg = dlc
            .send_offer_with_announcements(
                contract_input,
                counter_party,
                vec![vec![oracle_announcement]],
            )
            .map_err(|e| {
                log_error!(self.node_manager.logger, "Error sending DLC offer: {e}");
                e
            })?;

        let client = Client::new(&self.nostr.primary_key);
        client
            .add_relay(&self.nostr.dlc_handler.relay)
            .await
            .expect("Failed to add relay");
        client.connect().await;

        let contract_id = ContractId::from(msg.temporary_contract_id);

        let event = self.nostr.dlc_handler.create_wire_msg_event(
            pubkey,
            None,
            DlcMessageType::Normal(Message::Offer(msg)),
        )?;
        client.send_event(event).await?;

        client.disconnect().await?;

        Ok(contract_id)
    }

    /// Accepts a DLC offer with the given contract id. This in irrevocable and will in lock in the DLC unless it fails.
    ///
    /// This only sends the accept message, it does not guarantee that the counterparty will also sign the DLC.
    pub async fn accept_dlc_offer(&self, contract_id: [u8; 32]) -> Result<(), MutinyError> {
        let contract_id = ContractId::from(contract_id);
        let mut dlc = self.dlc.manager.lock().await;
        let (_, pubkey, msg) = dlc.accept_contract_offer(&contract_id)?;

        let client = Client::new(&self.nostr.primary_key);
        client
            .add_relay(&self.nostr.dlc_handler.relay)
            .await
            .expect("Failed to add relay");
        client.connect().await;

        let xonly = XOnlyPublicKey::from_slice(&pubkey.x_only_public_key().0.serialize())
            .expect("converting pubkey between crates should not fail");
        let event = self.nostr.dlc_handler.create_wire_msg_event(
            xonly,
            None,
            DlcMessageType::Normal(Message::Accept(msg)),
        )?;
        client.send_event(event).await?;

        client.disconnect().await?;

        Ok(())
    }

    /// Rejects a DLC offer with the given contract id. This will delete the DLC from the wallet.
    /// This is only possible if the DLC is in the Offered state or in a failed state, otherwise it will return an error.
    pub async fn reject_dlc_offer(&self, contract_id: [u8; 32]) -> Result<(), MutinyError> {
        let contract_id = ContractId::from(contract_id);
        let dlc = self.dlc.manager.lock().await;
        if let Some(contract) = dlc.get_store().get_contract(&contract_id)? {
            // Only delete the contract if it's an offer or failed,
            // otherwise we can't reject it without risking losing funds.
            match contract {
                Contract::Offered(_) => {
                    dlc.get_store().delete_contract(&contract_id)?;
                    return Ok(());
                }
                Contract::FailedAccept(_) | Contract::FailedSign(_) => {
                    // if we failed to accept or sign, we can delete the contract
                    dlc.get_store().delete_contract(&contract_id)?;
                    return Ok(());
                }
                _ => {
                    log_error!(
                        self.node_manager.logger,
                        "Cannot reject a contract that is active"
                    );
                    // todo probably want a more explicit error
                    return Err(MutinyError::DLCManagerError);
                }
            }
        }

        Err(MutinyError::NotFound)
    }

    /// Closes the DLC with the given contract id. If the oracle attestations are valid, this will broadcast the
    /// corresponding closing transaction. If the oracle attestations are not valid, this will return an error.
    pub async fn close_dlc(
        &self,
        contract_id: [u8; 32],
        attestation: OracleAttestation,
    ) -> Result<Contract, MutinyError> {
        let contract_id = ContractId::from(contract_id);
        let mut dlc = self.dlc.manager.lock().await;
        let contract = dlc
            .close_confirmed_contract(&contract_id, vec![(0, attestation)])
            .map_err(|e| {
                log_error!(self.node_manager.logger, "Error closing DLC: {e}");
                e
            })?;

        Ok(contract)
    }

    /// Lists all of the DLCs in the wallet, including offered, active, and failed.
    pub async fn list_dlcs(&self) -> Result<Vec<Contract>, MutinyError> {
        let dlc = self.dlc.manager.lock().await;
        let mut contracts = dlc.get_store().get_contracts()?;
        contracts.sort_by_key(|c| c.get_id());
        Ok(contracts)
    }

    /// The wallet's nostr key it uses to send and receive DLC offers.
    pub fn get_dlc_key(&self) -> XOnlyPublicKey {
        self.nostr.dlc_handler.public_key()
    }

    /// Starts a background process that will watch for nostr wallet connect & dlc events
    pub(crate) async fn start_nostr(&self) {
        let nostr = self.nostr.clone();
        let logger = self.logger.clone();
        let stop = self.stop.clone();
        let self_clone = self.clone();
        utils::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                };

                // clear in-active profiles, we used to have disabled and archived profiles
                // but now we just delete profiles
                if let Err(e) = nostr.remove_inactive_profiles() {
                    log_warn!(logger, "Failed to clear in-active NWC profiles: {e}");
                }

                // if a single-use profile's payment was successful in the background,
                // we can safely clear it now
                if let Err(e) = nostr
                    .clear_successful_single_use_profiles(&self_clone)
                    .await
                {
                    log_warn!(logger, "Failed to clear in-active NWC profiles: {e}");
                }

                if let Err(e) = nostr.clear_expired_nwc_invoices().await {
                    log_warn!(logger, "Failed to clear expired NWC invoices: {e}");
                }

                let client = Client::new(&nostr.primary_key);

                client
                    .add_relays(nostr.get_relays())
                    .await
                    .expect("Failed to add relays");
                client.connect().await;

                // subscribe to NWC events
                let mut last_filters = nostr.get_nwc_filters();
                client.subscribe(last_filters.clone()).await;

                // subscribe to DLC wire messages
                client
                    .subscribe(vec![nostr.dlc_handler.create_wire_msg_filter()])
                    .await;

                // handle NWC requests
                let mut notifications = client.notifications();

                let mut next_filter_check = crate::utils::now().as_secs() + 5;
                loop {
                    let read_fut = notifications.recv().fuse();
                    let delay_fut = Box::pin(utils::sleep(1_000)).fuse();

                    // Determine the time for filter check.
                    // Since delay runs every second, needs to allow for filter check to run too
                    let current_time = crate::utils::now().as_secs();
                    let time_until_next_filter_check =
                        (next_filter_check.saturating_sub(current_time)) * 1_000;
                    let filter_check_fut = Box::pin(utils::sleep(
                        time_until_next_filter_check.try_into().unwrap(),
                    ))
                    .fuse();

                    pin_mut!(read_fut, delay_fut, filter_check_fut);
                    select! {
                        notification = read_fut => {
                            match notification {
                                Ok(RelayPoolNotification::Event { event, .. }) => {
                                    if event.verify().is_ok() {
                                        match event.kind {
                                            Kind::WalletConnectRequest => {
                                                match nostr.handle_nwc_request(event, &self_clone).await {
                                                    Ok(Some(event)) => {
                                                        if let Err(e) = client.send_event(event).await {
                                                            log_warn!(logger, "Error sending NWC event: {e}");
                                                        }
                                                    }
                                                    Ok(None) => {} // no response
                                                    Err(e) => {
                                                        log_error!(logger, "Error handling NWC request: {e}");
                                                    }
                                                }
                                            }
                                            Kind::Ephemeral(28_888) => {
                                                match nostr.dlc_handler.handle_dlc_wire_event(event).await {
                                                    Err(e) => log_error!(logger, "Error handling DLC wire event: {e}"),
                                                    Ok(None) => {},
                                                    Ok(Some(event)) => {
                                                        if let Err(e) = client.send_event(event).await {
                                                            log_warn!(logger, "Error sending NWC event: {e}");
                                                        }
                                                    }
                                                }
                                            }
                                            _ => log_warn!(logger, "Received unexpected Nostr event: {event:?}"),
                                        }
                                    }
                                },
                                Ok(RelayPoolNotification::Message { .. }) => {}, // ignore messages
                                Ok(RelayPoolNotification::Shutdown) => break, // if we disconnect, we restart to reconnect
                                Ok(RelayPoolNotification::Stop) => {}, // Currently unused
                                Ok(RelayPoolNotification::RelayStatus { .. }) => {}, // Currently unused
                                Err(_) => break, // if we are erroring we should reconnect
                            }
                        }
                        _ = delay_fut => {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                        _ = filter_check_fut => {
                            // Check if the filters have changed
                            let current_filters = nostr.get_nwc_filters();
                            if current_filters != last_filters {
                                log_debug!(logger, "subscribing to new nwc filters");
                                client.subscribe(current_filters.clone()).await;
                                last_filters = current_filters;
                            }
                            // Set the time for the next filter check
                            next_filter_check = crate::utils::now().as_secs() + 5;
                        }
                    }
                }

                if let Err(e) = client.disconnect().await {
                    log_warn!(logger, "Error disconnecting from relays: {e}");
                }
            }
        });
    }

    /// Pays a lightning invoice from a federation (preferred) or node.
    /// An amount should only be provided if the invoice does not have an amount.
    /// Amountless invoices cannot be paid by a federation.
    /// The amount should be in satoshis.
    pub async fn pay_invoice(
        &self,
        inv: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        if inv.network() != self.network {
            return Err(MutinyError::IncorrectNetwork(inv.network()));
        }

        // check invoice is expired
        if inv.would_expire(utils::now()) {
            return Err(MutinyError::InvoiceExpired);
        }

        // Check the amount specified in the invoice, we need one to make the payment
        let send_msat = inv
            .amount_milli_satoshis()
            .or(amt_sats.map(|x| x * 1_000))
            .ok_or(MutinyError::InvoiceInvalid)?;

        // Try each federation first
        let federation_ids = self.list_federation_ids().await?;
        let mut last_federation_error = None;
        for federation_id in federation_ids {
            if let Some(fedimint_client) = self.federations.read().await.get(&federation_id) {
                // Check if the federation has enough balance
                let balance = fedimint_client.get_balance().await?;
                if balance >= send_msat / 1_000 {
                    // Try to pay the invoice using the federation
                    let payment_result = fedimint_client
                        .pay_invoice(inv.clone(), labels.clone())
                        .await;
                    match payment_result {
                        Ok(r) => {
                            self.storage.set_invoice_labels(inv.clone(), labels)?;
                            return Ok(r);
                        }
                        Err(e) => match e {
                            MutinyError::PaymentTimeout => return Err(e),
                            MutinyError::RoutingFailed => {
                                log_debug!(
                                    self.logger,
                                    "could not make payment through federation: {e}"
                                );
                                last_federation_error = Some(e);
                                continue;
                            }
                            _ => {
                                log_warn!(self.logger, "unhandled error: {e}");
                                last_federation_error = Some(e);
                            }
                        },
                    }
                }
                // If payment fails or invoice amount is None or balance is not sufficient, continue to next federation
            }
            // If federation client is not found, continue to next federation
        }

        // If any balance at all, then fallback to node manager for payment.
        // Take the error from the node manager as the priority.
        if self
            .node_manager
            .nodes
            .lock()
            .await
            .iter()
            .flat_map(|(_, n)| n.channel_manager.list_channels())
            .map(|c| c.balance_msat)
            .sum::<u64>()
            > 0
        {
            let res = self
                .node_manager
                .pay_invoice(None, inv, amt_sats, labels.clone())
                .await?;
            self.storage.set_invoice_labels(inv.clone(), labels)?;
            Ok(res)
        } else {
            Err(last_federation_error.unwrap_or(MutinyError::InsufficientBalance))
        }
    }

    /// Creates a BIP 21 invoice. This creates a new address and a lightning invoice.
    /// The lightning invoice may return errors related to the LSP. Check the error and
    /// fallback to `get_new_address` and warn the user that Lightning is not available.
    ///
    /// Errors that might be returned include:
    ///
    /// - [`MutinyError::LspGenericError`]: This is returned for various reasons, including if a
    ///   request to the LSP server fails for any reason, or if the server returns
    ///   a status other than 500 that can't be parsed into a `ProposalResponse`.
    ///
    /// - [`MutinyError::LspFundingError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message
    ///   stating "Cannot fund new channel at this time". This means that the LSP cannot support
    ///   a new channel at this time.
    ///
    /// - [`MutinyError::LspAmountTooHighError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message stating "Invoice
    ///   amount is too high". This means that the LSP cannot support the amount that the user
    ///   requested. The user should request a smaller amount from the LSP.
    ///
    /// - [`MutinyError::LspConnectionError`]: Returned if the LSP server returns an error with
    ///   a status of 500, indicating an "Internal Server Error", and a message that starts with
    ///   "Failed to connect to peer". This means that the LSP is not connected to our node.
    ///
    /// If the server returns a status of 500 with a different error message,
    /// a [`MutinyError::LspGenericError`] is returned.
    pub async fn create_bip21(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyBip21RawMaterials, MutinyError> {
        let invoice = if self.safe_mode {
            None
        } else {
            Some(
                self.create_lightning_invoice(amount, labels.clone())
                    .await?
                    .bolt11
                    .ok_or(MutinyError::InvoiceCreationFailed)?,
            )
        };

        let Ok(address) = self.node_manager.get_new_address(labels.clone()) else {
            return Err(MutinyError::WalletOperationFailed);
        };

        Ok(MutinyBip21RawMaterials {
            address,
            invoice,
            btc_amount: amount.map(|amount| bitcoin::Amount::from_sat(amount).to_btc().to_string()),
            labels,
        })
    }

    async fn create_lightning_invoice(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let federation_ids = self.list_federation_ids().await?;

        // Attempt to create federation invoice
        if !federation_ids.is_empty() {
            let federation_id = &federation_ids[0];
            let fedimint_client = self.federations.read().await.get(federation_id).cloned();

            if let Some(client) = fedimint_client {
                if let Ok(inv) = client
                    .get_invoice(amount.unwrap_or_default(), labels.clone())
                    .await
                {
                    self.storage
                        .set_invoice_labels(inv.bolt11.clone().expect("just created"), labels)?;
                    return Ok(inv);
                }
            }
        }

        // Fallback to node_manager invoice creation if no federation invoice created
        let inv = self.node_manager.create_invoice(amount).await?;
        self.storage
            .set_invoice_labels(inv.bolt11.clone().expect("just created"), labels)?;

        Ok(inv)
    }

    /// Gets the current balance of the wallet.
    /// This includes both on-chain, lightning funds, and federations.
    ///
    /// This will not include any funds in an unconfirmed lightning channel.
    pub async fn get_balance(&self) -> Result<MutinyBalance, MutinyError> {
        let ln_balance = self.node_manager.get_balance().await?;
        let federation_balance = self.get_total_federation_balance().await?;

        Ok(MutinyBalance::new(ln_balance, federation_balance))
    }

    /// Get the sorted activity list for lightning payments, channels, and txs.
    pub async fn get_activity(&self) -> Result<Vec<ActivityItem>, MutinyError> {
        // Get activity for lightning invoices
        let lightning = self
            .list_invoices()
            .map_err(|e| {
                log_warn!(self.logger, "Failed to get lightning activity: {e}");
                e
            })
            .unwrap_or_default();

        // Get activities from node manager
        let (closures, onchain) = self.node_manager.get_activity().await?;

        let mut activities = Vec::with_capacity(lightning.len() + onchain.len() + closures.len());
        for ln in lightning {
            // Only show paid and in-flight invoices
            match ln.status {
                HTLCStatus::Succeeded | HTLCStatus::InFlight => {
                    activities.push(ActivityItem::Lightning(Box::new(ln)));
                }
                HTLCStatus::Pending | HTLCStatus::Failed => {}
            }
        }
        for on in onchain {
            activities.push(ActivityItem::OnChain(on));
        }
        for chan in closures {
            activities.push(ActivityItem::ChannelClosed(chan));
        }

        // Sort all activities, newest first
        activities.sort_by(|a, b| b.cmp(a));

        Ok(activities)
    }

    pub fn list_invoices(&self) -> Result<Vec<MutinyInvoice>, MutinyError> {
        let mut inbound_invoices = self.list_payment_info_from_persisters(true)?;
        let mut outbound_invoices = self.list_payment_info_from_persisters(false)?;
        inbound_invoices.append(&mut outbound_invoices);
        Ok(inbound_invoices)
    }

    fn list_payment_info_from_persisters(
        &self,
        inbound: bool,
    ) -> Result<Vec<MutinyInvoice>, MutinyError> {
        let now = utils::now();
        let labels_map = self.storage.get_invoice_labels()?;

        Ok(list_payment_info(&self.storage, inbound)?
            .into_iter()
            .filter_map(|(h, i)| {
                let labels = match i.bolt11.clone() {
                    None => vec![],
                    Some(i) => labels_map.get(&i).cloned().unwrap_or_default(),
                };
                let mutiny_invoice = MutinyInvoice::from(i.clone(), h, inbound, labels).ok();

                // filter out expired invoices
                mutiny_invoice.filter(|invoice| {
                    !invoice.bolt11.as_ref().is_some_and(|b| b.would_expire(now))
                        || matches!(invoice.status, HTLCStatus::Succeeded | HTLCStatus::InFlight)
                })
            })
            .collect())
    }

    /// Gets an invoice.
    /// This includes sent and received invoices.
    pub async fn get_invoice(&self, invoice: &Bolt11Invoice) -> Result<MutinyInvoice, MutinyError> {
        self.get_invoice_by_hash(invoice.payment_hash()).await
    }

    /// Looks up an invoice by hash.
    /// This includes sent and received invoices.
    pub async fn get_invoice_by_hash(
        &self,
        hash: &sha256::Hash,
    ) -> Result<MutinyInvoice, MutinyError> {
        // First, try to find the invoice in the node manager
        if let Ok(invoice) = self.node_manager.get_invoice_by_hash(hash).await {
            return Ok(invoice);
        }

        // If not found in node manager, search in federations
        let federations = self.federations.read().await;
        for (_fed_id, federation) in federations.iter() {
            if let Ok(invoice) = federation.get_invoice_by_hash(hash).await {
                return Ok(invoice);
            }
        }

        Err(MutinyError::NotFound)
    }

    /// Checks whether or not the user is subscribed to Mutiny+.
    /// Submits a NWC string to keep the subscription active if not expired.
    ///
    /// Returns None if there's no subscription at all.
    /// Returns Some(u64) for their unix expiration timestamp, which may be in the
    /// past or in the future, depending on whether or not it is currently active.
    pub async fn check_subscribed(&self) -> Result<Option<u64>, MutinyError> {
        if let Some(subscription_client) = self.subscription_client.clone() {
            Ok(subscription_client.check_subscribed().await?)
        } else {
            Ok(None)
        }
    }

    /// Gets the subscription plans for Mutiny+ subscriptions
    pub async fn get_subscription_plans(&self) -> Result<Vec<Plan>, MutinyError> {
        if let Some(subscription_client) = self.subscription_client.clone() {
            Ok(subscription_client.get_plans().await?)
        } else {
            Ok(vec![])
        }
    }

    /// Subscribes to a Mutiny+ plan with a specific plan id.
    ///
    /// Returns a lightning invoice so that the plan can be paid for to start it.
    pub async fn subscribe_to_plan(&self, id: u8) -> Result<MutinyInvoice, MutinyError> {
        if let Some(subscription_client) = self.subscription_client.clone() {
            Ok(Bolt11Invoice::from_str(&subscription_client.subscribe_to_plan(id).await?)?.into())
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    /// Pay the subscription invoice. This will post a NWC automatically afterwards.
    pub async fn pay_subscription_invoice(
        &self,
        inv: &Bolt11Invoice,
        autopay: bool,
    ) -> Result<(), MutinyError> {
        if let Some(subscription_client) = self.subscription_client.clone() {
            // TODO if this times out, we should make the next part happen in EventManager
            self.pay_invoice(inv, None, vec![MUTINY_PLUS_SUBSCRIPTION_LABEL.to_string()])
                .await?;

            // now submit the NWC string if never created before
            self.ensure_mutiny_nwc_profile(subscription_client, autopay)
                .await?;

            Ok(())
        } else {
            Err(MutinyError::SubscriptionClientNotConfigured)
        }
    }

    async fn ensure_mutiny_nwc_profile(
        &self,
        subscription_client: Arc<subscription::MutinySubscriptionClient>,
        autopay: bool,
    ) -> Result<(), MutinyError> {
        let nwc_profiles = self.nostr.profiles();
        let reserved_profile_index = ReservedProfile::MutinySubscription.info().1;
        let profile_opt = nwc_profiles
            .iter()
            .find(|profile| profile.index == reserved_profile_index);

        match profile_opt {
            None => {
                // profile with the reserved index does not exist, create a new one
                let nwc = if autopay {
                    self.nostr
                        .create_new_nwc_profile(
                            ProfileType::Reserved(ReservedProfile::MutinySubscription),
                            SpendingConditions::Budget(BudgetedSpendingConditions {
                                budget: 21_000,
                                single_max: None,
                                payments: vec![],
                                period: BudgetPeriod::Month,
                            }),
                            NwcProfileTag::Subscription,
                        )
                        .await?
                        .nwc_uri
                } else {
                    self.nostr
                        .create_new_nwc_profile(
                            ProfileType::Reserved(ReservedProfile::MutinySubscription),
                            SpendingConditions::RequireApproval,
                            NwcProfileTag::Subscription,
                        )
                        .await?
                        .nwc_uri
                };

                if let Some(nwc) = nwc {
                    // only should have to submit the NWC if never created locally before
                    subscription_client.submit_nwc(nwc).await?;
                }
            }
            Some(profile) => {
                if profile.tag != NwcProfileTag::Subscription {
                    let mut nwc = profile.clone();
                    nwc.tag = NwcProfileTag::Subscription;
                    self.nostr.edit_profile(nwc)?;
                }
            }
        }

        // check if we have a contact, if not create one
        match self.storage.get_contact(MUTINY_PLUS_SUBSCRIPTION_LABEL)? {
            Some(_) => {}
            None => {
                let key = get_contact_key(MUTINY_PLUS_SUBSCRIPTION_LABEL);
                let contact = Contact {
                    name: MUTINY_PLUS_SUBSCRIPTION_LABEL.to_string(),
                    npub: None,
                    ln_address: None,
                    lnurl: None,
                    image_url: Some("https://void.cat/d/CZPXhnwjqRhULSjPJ3sXTE.webp".to_string()),
                    archived: None,
                    last_used: utils::now().as_secs(),
                };
                self.storage.set_data(key, contact, None)?;
            }
        }

        Ok(())
    }

    /// Makes a request to the primal api
    async fn primal_request(
        client: &reqwest::Client,
        url: &str,
        body: Value,
    ) -> Result<Vec<Value>, MutinyError> {
        client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|_| MutinyError::NostrError)?
            .json()
            .await
            .map_err(|_| MutinyError::NostrError)
    }

    /// Get contacts from the given npub and sync them to the wallet
    pub async fn sync_nostr_contacts(
        &self,
        primal_url: Option<&str>,
        npub: XOnlyPublicKey,
    ) -> Result<(), MutinyError> {
        let url = primal_url.unwrap_or("https://primal-cache.mutinywallet.com/api");
        let client = reqwest::Client::new();

        let body = json!(["contact_list", { "pubkey": npub } ]);
        let data: Vec<Value> = Self::primal_request(&client, url, body).await?;
        let mut metadata = parse_profile_metadata(data);

        let contacts = self.storage.get_contacts()?;

        // get contacts that weren't in our npub contacts list
        let missing_pks: Vec<String> = contacts
            .iter()
            .filter_map(|(_, c)| {
                if c.npub.is_some_and(|n| metadata.get(&n).is_none()) {
                    c.npub.map(|n| n.to_hex())
                } else {
                    None
                }
            })
            .collect();

        if !missing_pks.is_empty() {
            let body = json!(["user_infos", {"pubkeys": missing_pks }]);
            let data: Vec<Value> = Self::primal_request(&client, url, body).await?;
            let missing_metadata = parse_profile_metadata(data);
            metadata.extend(missing_metadata);
        }

        let mut updated_contacts: Vec<(String, Value)> =
            Vec::with_capacity(contacts.len() + metadata.len());

        for (id, contact) in contacts {
            if let Some(npub) = contact.npub {
                if let Some(meta) = metadata.get(&npub) {
                    let updated = contact.update_with_metadata(meta.clone());
                    metadata.remove(&npub);
                    updated_contacts.push((get_contact_key(id), serde_json::to_value(updated)?));
                }
            }
        }

        for (npub, meta) in metadata {
            let contact = Contact::create_from_metadata(npub, meta);

            if contact.name.is_empty() {
                log_debug!(
                    self.logger,
                    "Skipping creating contact with no name: {npub}"
                );
                continue;
            }

            // generate a uuid, this will be the "label" that we use to store the contact
            let id = Uuid::new_v4().to_string();
            let key = get_contact_key(&id);
            updated_contacts.push((key, serde_json::to_value(contact)?));

            let key = labels::get_label_item_key(&id);
            let label_item = LabelItem::default();
            updated_contacts.push((key, serde_json::to_value(label_item)?));
        }

        self.storage.set(updated_contacts)?;

        Ok(())
    }

    /// Stops all of the nodes and background processes.
    /// Returns after node has been stopped.
    pub async fn stop(&self) -> Result<(), MutinyError> {
        self.node_manager.stop().await
    }

    pub async fn change_password(
        &mut self,
        old: Option<String>,
        new: Option<String>,
    ) -> Result<(), MutinyError> {
        // check if old password is correct
        if old != self.storage.password().map(|s| s.to_owned()) {
            return Err(MutinyError::IncorrectPassword);
        }

        if old == new {
            return Err(MutinyError::SamePassword);
        }

        log_info!(self.logger, "Changing password");

        self.stop().await?;

        self.storage.start().await?;

        self.storage.change_password_and_rewrite_storage(
            old.filter(|s| !s.is_empty()),
            new.filter(|s| !s.is_empty()),
        )?;

        // There's not a good way to check that all the indexeddb
        // data is saved in the background. This should get better
        // once we have async saving, but for now just make sure
        // the user has saved their seed already.
        sleep(5_000).await;

        Ok(())
    }

    /// Resets BDK's keychain tracker. This will require a re-sync of the blockchain.
    ///
    /// This can be useful if you get stuck in a bad state.
    pub async fn reset_onchain_tracker(&mut self) -> Result<(), MutinyError> {
        self.node_manager.reset_onchain_tracker().await?;
        // sleep for 250ms to give time for the storage to write
        utils::sleep(250).await;

        self.stop().await?;

        // sleep for 250ms to give time for the node manager to stop
        utils::sleep(250).await;

        self.start().await?;

        self.node_manager.wallet.full_sync().await?;

        Ok(())
    }

    /// Deletes all the storage
    pub async fn delete_all(&self) -> Result<(), MutinyError> {
        self.storage.delete_all().await?;
        Ok(())
    }

    /// Restores the mnemonic after deleting the previous state.
    ///
    /// Backup the state beforehand. Does not restore lightning data.
    /// Should refresh or restart afterwards. Wallet should be stopped.
    pub async fn restore_mnemonic(mut storage: S, m: Mnemonic) -> Result<(), MutinyError> {
        // Delete our storage but insert some device specific data
        let device_id = storage.get_device_id()?;
        let logs: Option<Vec<String>> = storage.get_data(LOGGING_KEY)?;
        storage.stop();
        S::clear().await?;
        storage.start().await?;
        storage.insert_mnemonic(m)?;
        storage.set_data(NEED_FULL_SYNC_KEY.to_string(), true, None)?;
        storage.set_data(DEVICE_ID_KEY.to_string(), device_id, None)?;
        storage.set_data(LOGGING_KEY.to_string(), logs, None)?;

        Ok(())
    }

    /// Decodes a lightning invoice into useful information.
    /// Will return an error if the invoice is for a different network.
    pub fn decode_invoice(
        &self,
        invoice: Bolt11Invoice,
        network: Option<Network>,
    ) -> Result<MutinyInvoice, MutinyError> {
        if invoice.network() != network.unwrap_or(self.network) {
            return Err(MutinyError::IncorrectNetwork(invoice.network()));
        }

        Ok(invoice.into())
    }

    /// Adds a new federation based on its federation code
    pub async fn new_federation(
        &mut self,
        federation_code: InviteCode,
    ) -> Result<FederationIdentity, MutinyError> {
        create_new_federation(
            self.xprivkey,
            self.storage.clone(),
            self.network,
            self.logger.clone(),
            self.federation_storage.clone(),
            self.federations.clone(),
            federation_code,
        )
        .await
    }

    /// Lists the federation id's of the federation clients in the manager.
    pub async fn list_federations(&self) -> Result<Vec<FederationIdentity>, MutinyError> {
        let federations = self.federations.read().await;
        let federation_identities = federations
            .iter()
            .map(|(_, n)| n.get_mutiny_federation_identity())
            .collect();
        Ok(federation_identities)
    }

    /// Lists the federation id's of the federation clients in the manager.
    pub async fn list_federation_ids(&self) -> Result<Vec<FederationId>, MutinyError> {
        let federations = self.federations.read().await;
        let federation_identities = federations
            .iter()
            .map(|(_, n)| n.fedimint_client.federation_id())
            .collect();
        Ok(federation_identities)
    }

    /// Removes a federation by setting its archived status to true, based on the FederationId.
    pub async fn remove_federation(&self, federation_id: FederationId) -> Result<(), MutinyError> {
        let mut federations_guard = self.federations.write().await;

        if let Some(fedimint_client) = federations_guard.get(&federation_id) {
            let uuid = &fedimint_client.uuid;

            let mut federation_storage_guard = self.federation_storage.write().await;

            if federation_storage_guard.federations.contains_key(uuid) {
                federation_storage_guard.federations.remove(uuid);
                self.storage
                    .insert_federations(federation_storage_guard.clone())
                    .await?;
                federations_guard.remove(&federation_id);
            } else {
                return Err(MutinyError::NotFound);
            }
        } else {
            return Err(MutinyError::NotFound);
        }

        Ok(())
    }

    pub async fn get_total_federation_balance(&self) -> Result<u64, MutinyError> {
        let federation_ids = self.list_federation_ids().await?;
        let mut total_balance = 0;

        let federations = self.federations.read().await;
        for fed_id in federation_ids {
            let balance = federations
                .get(&fed_id)
                .ok_or(MutinyError::NotFound)?
                .get_balance()
                .await?;

            total_balance += balance;
        }

        Ok(total_balance)
    }

    pub async fn get_federation_balances(&self) -> Result<FederationBalances, MutinyError> {
        let federation_lock = self.federations.read().await;

        let federation_ids = self.list_federation_ids().await?;
        let mut balances = Vec::with_capacity(federation_ids.len());
        for fed_id in federation_ids {
            let fedimint_client = federation_lock.get(&fed_id).ok_or(MutinyError::NotFound)?;

            let balance = fedimint_client.get_balance().await?;
            let identity = fedimint_client.get_mutiny_federation_identity();

            balances.push(FederationBalance { identity, balance });
        }

        Ok(FederationBalances { balances })
    }

    /// Starts a background process that will check pending fedimint operations
    pub(crate) async fn start_fedimint_background_checker(&self) {
        let logger = self.logger.clone();
        let stop = self.stop.clone();
        let self_clone = self.clone();
        utils::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                };

                sleep(1000).await;
                let federation_lock = self_clone.federations.read().await;

                match self_clone.list_federation_ids().await {
                    Ok(federation_ids) => {
                        for fed_id in federation_ids {
                            match federation_lock.get(&fed_id) {
                                Some(fedimint_client) => {
                                    let _ = fedimint_client.check_activity().await.map_err(|e| {
                                        log_error!(logger, "error checking activity: {e}")
                                    });
                                }
                                None => {
                                    log_error!(
                                        logger,
                                        "could not get a federation from the lock: {}",
                                        fed_id
                                    )
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log_error!(logger, "could not list federations: {e}")
                    }
                }
            }
        });
    }

    /// Calls upon a LNURL to get the parameters for it.
    /// This contains what kind of LNURL it is (pay, withdrawal, auth, etc).
    // todo revamp LnUrlParams to be well designed
    pub async fn decode_lnurl(&self, lnurl: LnUrl) -> Result<LnUrlParams, MutinyError> {
        // handle LNURL-AUTH
        if lnurl.is_lnurl_auth() {
            return Ok(LnUrlParams {
                max: 0,
                min: 0,
                tag: "login".to_string(),
            });
        }

        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        let params = match response {
            LnUrlResponse::LnUrlPayResponse(pay) => LnUrlParams {
                max: pay.max_sendable,
                min: pay.min_sendable,
                tag: "payRequest".to_string(),
            },
            LnUrlResponse::LnUrlChannelResponse(_chan) => LnUrlParams {
                max: 0,
                min: 0,
                tag: "channelRequest".to_string(),
            },
            LnUrlResponse::LnUrlWithdrawResponse(withdraw) => LnUrlParams {
                max: withdraw.max_withdrawable,
                min: withdraw.min_withdrawable.unwrap_or(0),
                tag: "withdrawRequest".to_string(),
            },
        };

        Ok(params)
    }

    /// Calls upon a LNURL and pays it.
    /// This will fail if the LNURL is not a LNURL pay.
    pub async fn lnurl_pay(
        &self,
        lnurl: &LnUrl,
        amount_sats: u64,
        zap_npub: Option<XOnlyPublicKey>,
        mut labels: Vec<String>,
        comment: Option<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        match response {
            LnUrlResponse::LnUrlPayResponse(pay) => {
                let msats = amount_sats * 1000;

                // if user's npub is given, do an anon zap
                let (zap_request, comment) = match zap_npub {
                    Some(zap_npub) => {
                        let data = ZapRequestData {
                            public_key: zap_npub,
                            relays: vec![
                                "wss://nostr.mutinywallet.com".into(),
                                "wss://relay.primal.net".into(),
                            ],
                            message: comment.unwrap_or_default(),
                            amount: Some(msats),
                            lnurl: Some(lnurl.encode()),
                            event_id: None,
                            event_coordinate: None,
                        };
                        let event = nip57::anonymous_zap_request(data)?;

                        (Some(event.as_json()), None)
                    }
                    None => (None, comment.filter(|c| !c.is_empty())),
                };

                let invoice = self
                    .lnurl_client
                    .get_invoice(&pay, msats, zap_request, comment.as_deref())
                    .await?;

                let invoice = Bolt11Invoice::from_str(invoice.invoice())?;

                if invoice
                    .amount_milli_satoshis()
                    .is_some_and(|amt| msats == amt)
                {
                    // If we don't have any labels, see if this matches a contact
                    if labels.is_empty() {
                        if let Some(label) = self.storage.get_contact_for_lnurl(lnurl)? {
                            labels.insert(0, label)
                        }
                    }

                    self.pay_invoice(&invoice, None, labels).await
                } else {
                    log_error!(self.logger, "LNURL return invoice with incorrect amount");
                    Err(MutinyError::LnUrlFailure)
                }
            }
            LnUrlResponse::LnUrlWithdrawResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
            LnUrlResponse::LnUrlChannelResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
        }
    }

    /// Calls upon a LNURL and withdraws from it.
    /// This will fail if the LNURL is not a LNURL withdrawal.
    pub async fn lnurl_withdraw(
        &self,
        lnurl: &LnUrl,
        amount_sats: u64,
    ) -> Result<bool, MutinyError> {
        let response = self.lnurl_client.make_request(&lnurl.url).await?;

        match response {
            LnUrlResponse::LnUrlPayResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
            LnUrlResponse::LnUrlChannelResponse(_) => Err(MutinyError::IncorrectLnUrlFunction),
            LnUrlResponse::LnUrlWithdrawResponse(withdraw) => {
                // fixme: do we need to use this description?
                let _description = withdraw.default_description.clone();
                let mutiny_invoice = self
                    .create_invoice(Some(amount_sats), vec!["LNURL Withdrawal".to_string()])
                    .await?;
                let invoice_str = mutiny_invoice.bolt11.expect("Invoice should have bolt11");
                let res = self
                    .lnurl_client
                    .do_withdrawal(&withdraw, &invoice_str.to_string())
                    .await?;
                match res {
                    Response::Ok { .. } => Ok(true),
                    Response::Error { .. } => Ok(false),
                }
            }
        }
    }

    /// Authenticate with a LNURL-auth
    pub async fn lnurl_auth(&self, lnurl: LnUrl) -> Result<(), MutinyError> {
        make_lnurl_auth_connection(
            self.auth.clone(),
            self.lnurl_client.clone(),
            lnurl,
            self.logger.clone(),
        )
        .await
    }

    pub fn is_safe_mode(&self) -> bool {
        self.safe_mode
    }
}

impl<S: MutinyStorage> InvoiceHandler for MutinyWallet<S> {
    fn logger(&self) -> &MutinyLogger {
        self.logger.as_ref()
    }

    fn skip_hodl_invoices(&self) -> bool {
        self.skip_hodl_invoices
    }

    async fn get_outbound_payment_status(&self, payment_hash: &[u8; 32]) -> Option<HTLCStatus> {
        self.get_invoice_by_hash(&sha256::Hash::hash(payment_hash))
            .await
            .ok()
            .map(|p| p.status)
    }

    async fn pay_invoice(
        &self,
        invoice: &Bolt11Invoice,
        amt_sats: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        self.pay_invoice(invoice, amt_sats, labels).await
    }

    async fn create_invoice(
        &self,
        amount: Option<u64>,
        labels: Vec<String>,
    ) -> Result<MutinyInvoice, MutinyError> {
        self.create_lightning_invoice(amount, labels).await
    }
}

async fn create_federations<S: MutinyStorage>(
    federation_storage: FederationStorage,
    c: &MutinyWalletConfig,
    storage: &S,
    logger: &Arc<MutinyLogger>,
) -> Result<Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>, MutinyError> {
    let federations = federation_storage.federations.into_iter();
    let mut federation_map = HashMap::new();
    for federation_item in federations {
        let federation = FederationClient::new(
            federation_item.0,
            federation_item.1.federation_code.clone(),
            c.xprivkey,
            storage,
            c.network,
            logger.clone(),
        )
        .await?;

        let id = federation.fedimint_client.federation_id();

        federation_map.insert(id, Arc::new(federation));
    }
    let federations = Arc::new(RwLock::new(federation_map));
    Ok(federations)
}

// This will create a new federation and returns the Federation ID of the client created.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_new_federation<S: MutinyStorage>(
    xprivkey: ExtendedPrivKey,
    storage: S,
    network: Network,
    logger: Arc<MutinyLogger>,
    federation_storage: Arc<RwLock<FederationStorage>>,
    federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    federation_code: InviteCode,
) -> Result<FederationIdentity, MutinyError> {
    // Begin with a mutex lock so that nothing else can
    // save or alter the federation list while it is about to
    // be saved.
    let mut federation_mutex = federation_storage.write().await;

    // Get the current federations so that we can check if the new federation already exists
    let mut existing_federations = storage.get_federations()?;

    // Check if the federation already exists
    if existing_federations
        .federations
        .values()
        .any(|federation| federation.federation_code == federation_code)
    {
        return Err(MutinyError::InvalidArgumentsError);
    }

    // Create and save a new federation
    let next_federation_uuid = Uuid::new_v4().to_string();
    let next_federation = FederationIndex {
        federation_code: federation_code.clone(),
    };

    existing_federations.version += 1;
    existing_federations
        .federations
        .insert(next_federation_uuid.clone(), next_federation.clone());

    storage
        .insert_federations(existing_federations.clone())
        .await?;
    federation_mutex.federations = existing_federations.federations.clone();

    // now create the federation process and init it
    let new_federation = FederationClient::new(
        next_federation_uuid.clone(),
        federation_code,
        xprivkey,
        &storage,
        network,
        logger.clone(),
    )
    .await?;

    let federation_id = new_federation.fedimint_client.federation_id();
    let federation_name = new_federation.fedimint_client.get_meta("federation_name");
    let federation_expiry_timestamp = new_federation
        .fedimint_client
        .get_meta("federation_expiry_timestamp");
    let welcome_message = new_federation.fedimint_client.get_meta("welcome_message");
    federations
        .write()
        .await
        .insert(federation_id, Arc::new(new_federation));

    Ok(FederationIdentity {
        uuid: next_federation_uuid.clone(),
        federation_id,
        federation_name,
        federation_expiry_timestamp,
        welcome_message,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        encrypt::encryption_key_from_pass, generate_seed, nodemanager::NodeManager, MutinyWallet,
        MutinyWalletBuilder, MutinyWalletConfigBuilder,
    };
    use bitcoin::util::bip32::ExtendedPrivKey;
    use bitcoin::Network;

    use crate::test_utils::*;

    use crate::labels::{Contact, LabelStorage};
    use crate::storage::{MemoryStorage, MutinyStorage};
    use crate::utils::parse_npub;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn create_mutiny_wallet() {
        let test_name = "create_mutiny_wallet";
        log!("{}", test_name);

        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        mw.storage.insert_mnemonic(mnemonic).unwrap();
        assert!(NodeManager::has_node_manager(storage));
    }

    #[test]
    async fn restart_mutiny_wallet() {
        let test_name = "restart_mutiny_wallet";
        log!("{}", test_name);
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &[0; 32]).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mut mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");

        let first_seed = mw.node_manager.xprivkey;

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert_eq!(first_seed, mw.node_manager.xprivkey);
    }

    #[test]
    async fn restart_mutiny_wallet_with_nodes() {
        let test_name = "restart_mutiny_wallet_with_nodes";
        log!("{}", test_name);

        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &[0; 32]).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);

        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mut mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");

        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 1);
        assert!(mw.node_manager.new_node().await.is_ok());
        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 2);

        assert!(mw.stop().await.is_ok());
        assert!(mw.start().await.is_ok());
        assert_eq!(mw.node_manager.list_nodes().await.unwrap().len(), 2);
    }

    #[test]
    async fn restore_mutiny_mnemonic() {
        let test_name = "restore_mutiny_mnemonic";
        log!("{}", test_name);
        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        let seed = mw.node_manager.xprivkey;
        assert!(!seed.private_key.is_empty());

        // create a second mw and make sure it has a different seed
        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage2 = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage2.clone()));
        let xpriv2 = ExtendedPrivKey::new_master(network, &[0; 32]).unwrap();
        let config2 = MutinyWalletConfigBuilder::new(xpriv2)
            .with_network(network)
            .build();
        let mw2 = MutinyWalletBuilder::new(xpriv2, storage2.clone())
            .with_config(config2)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        let seed2 = mw2.node_manager.xprivkey;
        assert_ne!(seed, seed2);

        // now restore the first seed into the 2nd mutiny node
        mw2.stop().await.expect("should stop");
        drop(mw2);

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage3 = MemoryStorage::new(Some(pass), Some(cipher), None);

        MutinyWallet::restore_mnemonic(storage3.clone(), mnemonic.clone())
            .await
            .expect("mutiny wallet should restore");

        let new_mnemonic = storage3.get_mnemonic().unwrap().unwrap();
        let new_xpriv = ExtendedPrivKey::new_master(network, &new_mnemonic.to_seed("")).unwrap();
        let config3 = MutinyWalletConfigBuilder::new(new_xpriv)
            .with_network(network)
            .build();
        let mw3 = MutinyWalletBuilder::new(new_xpriv, storage3.clone())
            .with_config(config3)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        let restored_seed = mw3.node_manager.xprivkey;
        assert_eq!(seed, restored_seed);
    }

    #[test]
    async fn create_mutiny_wallet_safe_mode() {
        let test_name = "create_mutiny_wallet";
        log!("{}", test_name);

        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();

        let pass = uuid::Uuid::new_v4().to_string();
        let cipher = encryption_key_from_pass(&pass).unwrap();
        let storage = MemoryStorage::new(Some(pass), Some(cipher), None);
        assert!(!NodeManager::has_node_manager(storage.clone()));
        let mut config_builder = MutinyWalletConfigBuilder::new(xpriv).with_network(network);
        config_builder.with_safe_mode();
        let config = config_builder.build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");
        mw.storage.insert_mnemonic(mnemonic).unwrap();
        assert!(NodeManager::has_node_manager(storage));

        let bip21 = mw.create_bip21(None, vec![]).await.unwrap();
        assert!(bip21.invoice.is_none());

        let new_node = mw.node_manager.new_node().await;
        assert!(new_node.is_err());
    }

    #[test]
    async fn sync_nostr_contacts() {
        let npub =
            parse_npub("npub18s7md9ytv8r240jmag5j037huupk5jnsk94adykeaxtvc6lyftesuw5ydl").unwrap();
        let ben =
            parse_npub("npub1u8lnhlw5usp3t9vmpz60ejpyt649z33hu82wc2hpv6m5xdqmuxhs46turz").unwrap();
        let tony =
            parse_npub("npub1t0nyg64g5vwprva52wlcmt7fkdr07v5dr7s35raq9g0xgc0k4xcsedjgqv").unwrap();

        // create wallet
        let mnemonic = generate_seed(12).unwrap();
        let network = Network::Regtest;
        let xpriv = ExtendedPrivKey::new_master(network, &mnemonic.to_seed("")).unwrap();
        let storage = MemoryStorage::new(None, None, None);
        let config = MutinyWalletConfigBuilder::new(xpriv)
            .with_network(network)
            .build();
        let mw = MutinyWalletBuilder::new(xpriv, storage.clone())
            .with_config(config)
            .build()
            .await
            .expect("mutiny wallet should initialize");

        // sync contacts
        mw.sync_nostr_contacts(None, npub)
            .await
            .expect("synced contacts");

        // first sync should yield just ben's contact
        let contacts = mw
            .storage
            .get_contacts()
            .unwrap()
            .into_values()
            .collect::<Vec<_>>();
        assert_eq!(contacts.len(), 1);
        let contact = contacts.first().unwrap();
        assert_eq!(contact.npub, Some(ben));
        assert!(!contact.archived.unwrap_or(false));
        assert!(contact.image_url.is_some());
        assert!(contact.ln_address.is_some());
        assert!(!contact.name.is_empty());

        // add tony as a contact with incomplete info
        let incorrect_name = "incorrect name".to_string();
        let new_contact = Contact {
            name: incorrect_name.clone(),
            npub: Some(tony),
            ..Default::default()
        };
        let id = mw.storage.create_new_contact(new_contact).unwrap();

        // sync contacts again, tony's contact should be correct
        mw.sync_nostr_contacts(None, npub)
            .await
            .expect("synced contacts");

        let contacts = mw.storage.get_contacts().unwrap();
        assert_eq!(contacts.len(), 2);
        let contact = contacts.get(&id).unwrap();
        assert_eq!(contact.npub, Some(tony));
        assert!(!contact.archived.unwrap_or(false));
        assert!(contact.image_url.is_some());
        assert!(contact.ln_address.is_some());
        assert_ne!(contact.name, incorrect_name);
    }
}
