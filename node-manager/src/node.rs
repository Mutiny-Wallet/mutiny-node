use crate::chain::MutinyChain;
use crate::error::MutinyStorageError;
use crate::event::{EventHandler, HTLCStatus, MillisatAmount, PaymentInfo};
use crate::ldkstorage::{MutinyNodePersister, PhantomChannelManager};
use crate::localstorage::MutinyBrowserStorage;
use crate::nodemanager::{MutinyInvoice, MutinyInvoiceParams};
use crate::peermanager::{PeerManager, PeerManagerImpl};
use crate::proxy::WsProxy;
use crate::socket::WsTcpSocketDescriptor;
use crate::socket::{schedule_descriptor_read, MultiWsSocketDescriptor, WsSocketDescriptor};
use crate::utils::{currency_from_network, sleep};
use crate::wallet::MutinyWallet;
use crate::{
    background::{process_events_async, GossipSync},
    error::MutinyError,
    keymanager::{create_keys_manager, pubkey_from_keys_manager},
    logging::MutinyLogger,
    nodemanager::NodeIndex,
};
use anyhow::Context;
use bdk::blockchain::EsploraBlockchain;
use bip39::Mnemonic;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::Network;
use bitcoin_hashes::hex::ToHex;
use lightning::chain::keysinterface::{InMemorySigner, PhantomKeysManager, Recipient};
use lightning::chain::{chainmonitor, Filter, Watch};
use lightning::ln::channelmanager::PhantomRouteHints;
use lightning::ln::msgs::NetAddress;
use lightning::ln::peer_handler::{
    IgnoringMessageHandler, MessageHandler as LdkMessageHandler,
    SocketDescriptor as LdkSocketDescriptor,
};
use lightning::ln::{PaymentHash, PaymentPreimage};
use lightning::routing::gossip;
use lightning::routing::router::DefaultRouter;
use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};
use lightning::util::config::{ChannelHandshakeConfig, ChannelHandshakeLimits, UserConfig};
use lightning::util::logger::{Logger, Record};
use lightning::util::ser::Writeable;
use lightning_invoice::utils::create_invoice_from_channelmanager_and_duration_since_epoch;
use lightning_invoice::{payment, Invoice};
use log::{debug, error, info, trace};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use wasm_bindgen_futures::spawn_local;

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<MutinyLogger>>;

pub(crate) type MessageHandler = LdkMessageHandler<
    Arc<PhantomChannelManager>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
>;

pub(crate) type ChainMonitor = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<dyn Filter + Send + Sync>,
    Arc<MutinyChain>,
    Arc<MutinyChain>,
    Arc<MutinyLogger>,
    Arc<MutinyNodePersister>,
>;

pub(crate) type InvoicePayer<E> =
    payment::InvoicePayer<Arc<PhantomChannelManager>, Router, Arc<MutinyLogger>, E>;

type Router = DefaultRouter<
    Arc<NetworkGraph>,
    Arc<MutinyLogger>,
    Arc<Mutex<ProbabilisticScorer<Arc<NetworkGraph>, Arc<MutinyLogger>>>>,
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionType {
    Tcp(String),
    Mutiny(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PubkeyConnectionInfo {
    pub pubkey: PublicKey,
    pub connection_type: ConnectionType,
    pub original_connection_string: String,
}

impl PubkeyConnectionInfo {
    pub fn new(connection: String) -> Result<Self, MutinyError> {
        if connection.is_empty() {
            return Err(MutinyError::PeerInfoParseFailed)
                .context("connect_peer requires peer connection info")?;
        };
        let connection = connection.to_lowercase();
        if connection.starts_with("mutiny:") {
            let stripped_connection = connection.strip_prefix("mutiny:").expect("should strip");
            let (pubkey, peer_addr_str) =
                split_peer_connection_string(stripped_connection.to_string())?;
            Ok(Self {
                pubkey,
                connection_type: ConnectionType::Mutiny(peer_addr_str),
                original_connection_string: connection.to_string(),
            })
        } else {
            let (pubkey, peer_addr_str) = parse_peer_info(connection.clone())?;
            Ok(Self {
                pubkey,
                connection_type: ConnectionType::Tcp(peer_addr_str),
                original_connection_string: connection,
            })
        }
    }
}

pub(crate) struct Node {
    pub _uuid: String,
    pub pubkey: PublicKey,
    pub peer_manager: Arc<dyn PeerManager>,
    pub keys_manager: Arc<PhantomKeysManager>,
    pub channel_manager: Arc<PhantomChannelManager>,
    pub chain_monitor: Arc<ChainMonitor>,
    pub invoice_payer: Arc<InvoicePayer<EventHandler>>,
    network: Network,
    pub persister: Arc<MutinyNodePersister>,
    logger: Arc<MutinyLogger>,
    websocket_proxy_addr: String,
    multi_socket: MultiWsSocketDescriptor,
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn new(
        node_index: NodeIndex,
        mnemonic: Mnemonic,
        storage: MutinyBrowserStorage,
        chain: Arc<MutinyChain>,
        wallet: Arc<MutinyWallet>,
        network: Network,
        websocket_proxy_addr: String,
        esplora: Arc<EsploraBlockchain>,
    ) -> Result<Self, MutinyError> {
        info!("initialized a new node: {}", node_index.uuid);

        let logger = Arc::new(MutinyLogger::default());

        let keys_manager = Arc::new(create_keys_manager(mnemonic, node_index.child_index));
        let pubkey = pubkey_from_keys_manager(&keys_manager);

        // init the persister
        let persister = Arc::new(MutinyNodePersister::new(node_index.uuid.clone(), storage));

        // init chain monitor
        let chain_monitor: Arc<ChainMonitor> = Arc::new(ChainMonitor::new(
            None,
            chain.clone(),
            logger.clone(),
            chain.clone(),
            persister.clone(),
        ));

        // read channelmonitor state from disk
        let channel_monitors = persister
            .read_channel_monitors(keys_manager.clone())
            .map_err(|e| MutinyError::ReadError {
                source: MutinyStorageError::Other(e.into()),
            })?;

        // init channel manager
        let mut read_channel_manager = persister
            .read_channel_manager(
                network,
                chain_monitor.clone(),
                chain.clone(),
                logger.clone(),
                keys_manager.clone(),
                channel_monitors,
                esplora,
            )
            .await?;

        let channel_manager: Arc<PhantomChannelManager> =
            Arc::new(read_channel_manager.channel_manager);

        // init peer manager
        let ln_msg_handler = MessageHandler {
            chan_handler: channel_manager.clone(),
            route_handler: Arc::new(IgnoringMessageHandler {}),
            onion_message_handler: Arc::new(IgnoringMessageHandler {}),
        };

        // init event handler
        let event_handler = EventHandler::new(
            channel_manager.clone(),
            chain.clone(),
            wallet.clone(),
            keys_manager.clone(),
            persister.clone(),
            network,
            logger.clone(),
        );
        let peer_man = Arc::new(create_peer_manager(
            keys_manager.clone(),
            ln_msg_handler,
            logger.clone(),
        ));

        // sync to chain tip
        if read_channel_manager.is_restarting {
            let mut chain_listener_channel_monitors = Vec::new();
            for (blockhash, channel_monitor) in read_channel_manager.channel_monitors.drain(..) {
                // Get channel monitor ready to sync
                channel_monitor.load_outputs_to_watch(&chain);

                let outpoint = channel_monitor.get_funding_txo().0;
                chain_listener_channel_monitors.push((
                    blockhash,
                    (
                        channel_monitor,
                        chain.clone(),
                        chain.clone(),
                        logger.clone(),
                    ),
                    outpoint,
                ));
            }

            // give channel monitors to chain monitor
            for item in chain_listener_channel_monitors.drain(..) {
                let channel_monitor = item.1 .0;
                let funding_outpoint = item.2;
                chain_monitor
                    .clone()
                    .watch_channel(funding_outpoint, channel_monitor);
            }
        }

        // todo use RGS
        // get network graph
        let genesis_hash = genesis_block(network).block_hash();
        let network_graph = Arc::new(persister.read_network_graph(genesis_hash, logger.clone()));

        // create scorer
        let params = ProbabilisticScoringParameters::default();
        let scorer = Arc::new(Mutex::new(ProbabilisticScorer::new(
            params,
            network_graph.clone(),
            logger.clone(),
        )));

        let router: Router = DefaultRouter::new(
            network_graph,
            logger.clone(),
            keys_manager.get_secure_random_bytes(),
            scorer.clone(),
        );

        let invoice_payer: Arc<InvoicePayer<EventHandler>> = Arc::new(InvoicePayer::new(
            Arc::clone(&channel_manager),
            router,
            Arc::clone(&logger),
            event_handler.clone(),
            payment::Retry::Attempts(5),
        ));

        let background_persister = persister.clone();
        let background_event_handler = event_handler.clone();
        let background_processor_logger = logger.clone();
        let background_processor_peer_manager = peer_man.clone();
        let background_processor_channel_manager = channel_manager.clone();
        let background_chain_monitor = chain_monitor.clone();

        spawn_local(async move {
            loop {
                let gs: GossipSync<_, _, &NetworkGraph, _, Arc<MutinyLogger>> = GossipSync::none();
                let ev = background_event_handler.clone();
                process_events_async(
                    background_persister.clone(),
                    |e| ev.handle_event(e),
                    background_chain_monitor.clone(),
                    background_processor_channel_manager.clone(),
                    gs,
                    background_processor_peer_manager.clone(),
                    background_processor_logger.clone(),
                    Some(scorer.clone()),
                    |d| async move {
                        sleep(d.as_millis() as i32).await;
                        false
                    },
                )
                .await
                .expect("Failed to process events");
            }
        });

        // create a connection immediately to the user's
        // specified mutiny websocket proxy provider.
        let self_connection = PubkeyConnectionInfo {
            pubkey,
            connection_type: ConnectionType::Mutiny(websocket_proxy_addr.to_string()),
            original_connection_string: format!("mutiny:{pubkey}@{websocket_proxy_addr}"),
        };
        let main_proxy =
            WsProxy::new(websocket_proxy_addr.to_string(), self_connection.clone()).await?;
        let multi_socket = MultiWsSocketDescriptor::new(
            Arc::new(main_proxy),
            peer_man.clone(),
            pubkey.serialize().to_vec(),
        );
        multi_socket.listen();

        // keep trying to reconnect to our multi socket proxy
        let mut multi_socket_reconnect = multi_socket.clone();
        let websocket_proxy_addr_copy = websocket_proxy_addr.clone();
        let self_connection_copy = self_connection.clone();
        spawn_local(async move {
            loop {
                if !multi_socket_reconnect.connected() {
                    debug!("got disconnected from multi socket proxy, going to reconnect");
                    match WsProxy::new(
                        websocket_proxy_addr_copy.to_string(),
                        self_connection_copy.clone(),
                    )
                    .await
                    {
                        Ok(main_proxy) => {
                            multi_socket_reconnect.reconnect(Arc::new(main_proxy)).await;
                        }
                        Err(_) => {
                            sleep(5 * 1000).await;
                            continue;
                        }
                    };
                }
                sleep(5 * 1000).await;
            }
        });

        // try to connect to peers we already have a channel with
        let connect_peer_man = peer_man.clone();
        let connect_persister = persister.clone();
        let connect_proxy = websocket_proxy_addr.clone();
        let connect_logger = logger.clone();
        let connect_multi_socket = multi_socket.clone();
        spawn_local(async move {
            loop {
                // if we aren't connected to master socket
                // then don't try to connect peer
                if !connect_multi_socket.connected() {
                    sleep(5 * 1000).await;
                    continue;
                }

                let peer_connections = connect_persister.list_peer_connection_info();
                let current_connections = connect_peer_man.get_peer_node_ids();

                let not_connected: Vec<&(PublicKey, String)> = peer_connections
                    .iter()
                    .filter(|(p, _)| !current_connections.contains(p))
                    .collect();

                for (pubkey, conn_str) in not_connected.iter() {
                    connect_logger.log(&Record::new(
                        lightning::util::logger::Level::Debug,
                        format_args!("DEBUG: going to auto connect to peer: {pubkey}"),
                        "node",
                        "",
                        0,
                    ));
                    let peer_connection_info = match PubkeyConnectionInfo::new(conn_str.to_string())
                    {
                        Ok(p) => p,
                        Err(e) => {
                            connect_logger.log(&Record::new(
                                lightning::util::logger::Level::Error,
                                format_args!("ERROR: could not parse connection info: {e}"),
                                "node",
                                "",
                                0,
                            ));
                            continue;
                        }
                    };
                    match connect_peer(
                        connect_multi_socket.clone(),
                        connect_proxy.clone(),
                        peer_connection_info,
                        connect_peer_man.clone(),
                    )
                    .await
                    {
                        Ok(_) => {
                            connect_logger.log(&Record::new(
                                lightning::util::logger::Level::Debug,
                                format_args!("DEBUG: auto connected peer: {pubkey}"),
                                "node",
                                "",
                                0,
                            ));
                        }
                        Err(e) => {
                            connect_logger.log(&Record::new(
                                lightning::util::logger::Level::Warn,
                                format_args!("WARN: could not auto connect peer: {e}"),
                                "node",
                                "",
                                0,
                            ));
                        }
                    }
                }
                sleep(5 * 1000).await;
            }
        });

        Ok(Node {
            _uuid: node_index.uuid,
            pubkey,
            peer_manager: peer_man,
            keys_manager,
            channel_manager,
            chain_monitor,
            invoice_payer,
            network,
            persister,
            logger,
            websocket_proxy_addr,
            multi_socket,
        })
    }

    pub async fn connect_peer(
        &self,
        peer_connection_info: PubkeyConnectionInfo,
    ) -> Result<(), MutinyError> {
        match connect_peer_if_necessary(
            self.multi_socket.clone(),
            self.websocket_proxy_addr.clone(),
            peer_connection_info.clone(),
            self.peer_manager.clone(),
        )
        .await
        {
            Ok(_) => {
                let pubkey = peer_connection_info.pubkey.to_string();

                // if we have the connection info saved in storage, update it if we need to
                // otherwise cache it in temp_peer_connection_map so we can later save it
                // if we open a channel in the future.
                if let Some(saved) = self.persister.read_peer_connection_info(pubkey.clone()) {
                    if saved != peer_connection_info.original_connection_string {
                        match self.persister.persist_peer_connection_info(
                            pubkey,
                            peer_connection_info.original_connection_string,
                        ) {
                            Ok(_) => (),
                            Err(_) => self.logger.log(&Record::new(
                                lightning::util::logger::Level::Warn,
                                format_args!("WARN: could not store peer connection info",),
                                "node",
                                "",
                                0,
                            )),
                        }
                    }
                } else {
                    // store this so we can reconnect later
                    if self
                        .persister
                        .persist_peer_connection_info(
                            pubkey,
                            peer_connection_info.original_connection_string,
                        )
                        .is_err()
                    {
                        self.logger.log(&Record::new(
                            lightning::util::logger::Level::Warn,
                            format_args!("WARN: could not store peer connection info",),
                            "node",
                            "",
                            0,
                        ));
                    }
                }

                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn disconnect_peer(&self, peer_id: PublicKey) {
        self.peer_manager.disconnect_by_node_id(peer_id, false);
    }

    pub fn get_phantom_route_hint(&self) -> PhantomRouteHints {
        self.channel_manager.get_phantom_route_hints()
    }

    pub fn create_invoice(
        &self,
        amount_sat: Option<u64>,
        description: String,
        route_hints: Option<Vec<PhantomRouteHints>>,
    ) -> Result<Invoice, MutinyError> {
        let amount_msat = amount_sat.map(|s| s * 1_000);
        let invoice_res = match route_hints {
            None => {
                let now = crate::utils::now();
                create_invoice_from_channelmanager_and_duration_since_epoch(
                    &self.channel_manager.clone(),
                    self.keys_manager.clone(),
                    self.logger.clone(),
                    currency_from_network(self.network),
                    amount_msat,
                    description,
                    now,
                    1500,
                )
            }
            Some(r) => create_phantom_invoice::<InMemorySigner, Arc<PhantomKeysManager>>(
                amount_msat,
                None,
                description,
                1500,
                r,
                self.keys_manager.clone(),
                currency_from_network(self.network),
            ),
        };
        let invoice = invoice_res.map_err(|e| {
            self.logger.log(&Record::new(
                lightning::util::logger::Level::Error,
                format_args!("ERROR: could not generate invoice: {e}"),
                "node",
                "",
                0,
            ));
            MutinyError::InvoiceCreationFailed
        })?;

        let last_update = crate::utils::now().as_secs();
        let payment_hash = PaymentHash(invoice.payment_hash().into_inner());
        let payment_info = PaymentInfo {
            preimage: None,
            secret: Some(invoice.payment_secret().0),
            status: HTLCStatus::Pending,
            amt_msat: MillisatAmount(amount_msat),
            fee_paid_msat: None,
            bolt11: Some(invoice.to_string()),
            last_update,
        };
        self.persister
            .persist_payment_info(payment_hash, payment_info, true)
            .map_err(|e| {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Error,
                    format_args!("ERROR: could not persist payment info: {e}"),
                    "node",
                    "",
                    0,
                ));
                MutinyError::InvoiceCreationFailed
            })?;

        self.logger.log(&Record::new(
            lightning::util::logger::Level::Info,
            format_args!("SUCCESS: generated invoice: {invoice}",),
            "node",
            "",
            0,
        ));

        Ok(invoice)
    }

    pub fn get_invoice(&self, invoice: Invoice) -> Result<MutinyInvoice, MutinyError> {
        let payment_hash = invoice.payment_hash();
        let (payment_info, inbound) = self.get_payment_info_from_persisters(payment_hash)?;
        let mut mutiny_invoice: MutinyInvoice = invoice.into();
        mutiny_invoice.is_send = !inbound;
        mutiny_invoice.paid = matches!(payment_info.status, HTLCStatus::Succeeded);
        Ok(mutiny_invoice)
    }

    pub fn list_invoices(&self) -> Result<Vec<MutinyInvoice>, MutinyError> {
        let mut inbound_invoices = self.list_payment_info_from_persisters(true);
        let mut outbound_invoices = self.list_payment_info_from_persisters(false);
        inbound_invoices.append(&mut outbound_invoices);
        Ok(inbound_invoices)
    }

    fn list_payment_info_from_persisters(&self, inbound: bool) -> Vec<MutinyInvoice> {
        let now = crate::utils::now();
        self.persister
            .list_payment_info(inbound)
            .into_iter()
            .filter_map(|(h, i)| match i.bolt11 {
                Some(bolt11) => {
                    // Construct an invoice from a bolt11, easy
                    let invoice_res = Invoice::from_str(&bolt11).map_err(Into::<MutinyError>::into);
                    match invoice_res {
                        Ok(invoice) => {
                            if invoice.would_expire(now)
                                && !matches!(i.status, HTLCStatus::Succeeded | HTLCStatus::InFlight)
                            {
                                None
                            } else {
                                let mut mutiny_invoice: MutinyInvoice = invoice.clone().into();
                                mutiny_invoice.is_send = !inbound;
                                mutiny_invoice.paid = matches!(i.status, HTLCStatus::Succeeded);
                                mutiny_invoice.amount_sats =
                                    if let Some(inv_amt) = invoice.amount_milli_satoshis() {
                                        if inv_amt == 0 {
                                            i.amt_msat.0.map(|a| a / 1_000)
                                        } else {
                                            Some(inv_amt / 1_000)
                                        }
                                    } else {
                                        i.amt_msat.0.map(|a| a / 1_000)
                                    };
                                Some(mutiny_invoice)
                            }
                        }
                        Err(_) => None,
                    }
                }
                None => {
                    // Constructing MutinyInvoice from no invoice, harder
                    let paid = matches!(i.status, HTLCStatus::Succeeded);
                    let amount_sats: Option<u64> = i.amt_msat.0.map(|s| s / 1_000);
                    let fees_paid = i.fee_paid_msat.map(|f| f / 1_000);
                    let preimage = i.preimage.map(|p| p.to_hex());
                    let params = MutinyInvoiceParams {
                        bolt11: None,
                        description: None,
                        payment_hash: h,
                        preimage,
                        payee_pubkey: None,
                        amount_sats,
                        expire: i.last_update,
                        paid,
                        fees_paid,
                        is_send: !inbound,
                    };
                    Some(MutinyInvoice::new(params))
                }
            })
            .collect()
    }

    fn get_payment_info_from_persisters(
        &self,
        payment_hash: &bitcoin_hashes::sha256::Hash,
    ) -> Result<(PaymentInfo, bool), MutinyError> {
        // try inbound first
        if let Some(payment_info) = self.persister.read_payment_info(
            PaymentHash(payment_hash.into_inner()),
            true,
            self.logger.clone(),
        ) {
            return Ok((payment_info, true));
        }

        // if no inbound check outbound
        match self.persister.read_payment_info(
            PaymentHash(payment_hash.into_inner()),
            false,
            self.logger.clone(),
        ) {
            Some(payment_info) => Ok((payment_info, false)),
            None => Err(MutinyError::InvoiceInvalid),
        }
    }

    /// pay_invoice sends off the payment but does not wait for results
    pub fn pay_invoice(
        &self,
        invoice: Invoice,
        amt_sats: Option<u64>,
    ) -> Result<MutinyInvoice, MutinyError> {
        let (pay_result, amt_msat) = if invoice.amount_milli_satoshis().is_none() {
            if amt_sats.is_none() {
                return Err(MutinyError::InvoiceInvalid);
            }
            let amt_msats = amt_sats.unwrap() * 1_000;
            (
                self.invoice_payer
                    .pay_zero_value_invoice(&invoice, amt_msats),
                amt_msats,
            )
        } else {
            if amt_sats.is_some() {
                return Err(MutinyError::InvoiceInvalid);
            }
            (
                self.invoice_payer.pay_invoice(&invoice),
                invoice.amount_milli_satoshis().unwrap(),
            )
        };

        let last_update = crate::utils::now().as_secs();
        let mut payment_info = PaymentInfo {
            preimage: None,
            secret: None,
            status: HTLCStatus::InFlight,
            amt_msat: MillisatAmount(Some(amt_msat)),
            fee_paid_msat: None,
            bolt11: Some(invoice.to_string()),
            last_update,
        };
        self.persister.persist_payment_info(
            PaymentHash(invoice.payment_hash().into_inner()),
            payment_info.clone(),
            false,
        )?;

        match pay_result {
            Ok(_) => {
                let mut mutiny_invoice: MutinyInvoice = invoice.into();
                mutiny_invoice.paid = false;
                mutiny_invoice.is_send = true;
                Ok(mutiny_invoice)
            }
            Err(e) => {
                error!("failed to make payment: {:?}", e);
                // call list channels to see what our channels are
                let current_channels = self.channel_manager.list_channels();
                debug!("current channel details: {:?}", current_channels);

                payment_info.status = HTLCStatus::Failed;
                self.persister.persist_payment_info(
                    PaymentHash(invoice.payment_hash().into_inner()),
                    payment_info,
                    false,
                )?;
                Err(MutinyError::RoutingFailed)
            }
        }
    }

    /// keysend sends off the payment but does not wait for results
    pub fn keysend(&self, to_node: PublicKey, amt_sats: u64) -> Result<MutinyInvoice, MutinyError> {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| MutinyError::SeedGenerationFailed)?;
        let preimage = PaymentPreimage(entropy);

        let amt_msats = amt_sats * 1000;

        let pay_result = self
            .invoice_payer
            .pay_pubkey(to_node, preimage, amt_msats, 40);

        let payment_hash = PaymentHash(Sha256::hash(&preimage.0).into_inner());

        let last_update = crate::utils::now().as_secs();
        let mut payment_info = PaymentInfo {
            preimage: Some(preimage.0),
            secret: None,
            status: HTLCStatus::InFlight,
            amt_msat: MillisatAmount(Some(amt_msats)),
            fee_paid_msat: None,
            bolt11: None,
            last_update,
        };

        self.persister
            .persist_payment_info(payment_hash, payment_info.clone(), false)?;

        match pay_result {
            Ok(_) => {
                let params = MutinyInvoiceParams {
                    bolt11: None,
                    description: None,
                    payment_hash: payment_hash.0.to_hex(),
                    preimage: Some(preimage.0.to_hex()),
                    payee_pubkey: Some(to_node.to_hex()),
                    amount_sats: Some(amt_sats),
                    expire: payment_info.last_update,
                    paid: false,
                    fees_paid: None,
                    is_send: true,
                };
                let mutiny_invoice: MutinyInvoice = MutinyInvoice::new(params);
                Ok(mutiny_invoice)
            }
            Err(_) => {
                payment_info.status = HTLCStatus::Failed;
                self.persister
                    .persist_payment_info(payment_hash, payment_info, false)?;
                Err(MutinyError::RoutingFailed)
            }
        }
    }

    pub async fn open_channel(
        &self,
        pubkey: PublicKey,
        amount_sat: u64,
    ) -> Result<[u8; 32], MutinyError> {
        let config = default_user_config();
        match self
            .channel_manager
            .create_channel(pubkey, amount_sat, 0, 0, Some(config))
        {
            Ok(res) => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Info,
                    format_args!("SUCCESS: channel initiated with peer: {pubkey:?}"),
                    "node",
                    "",
                    0,
                ));
                Ok(res)
            }
            Err(e) => {
                self.logger.log(&Record::new(
                    lightning::util::logger::Level::Error,
                    format_args!("ERROR: failed to open channel to pubkey {pubkey:?}: {e:?}"),
                    "node",
                    "",
                    0,
                ));
                Err(MutinyError::ChannelCreationFailed)
            }
        }
    }
}

pub(crate) async fn connect_peer_if_necessary(
    multi_socket: MultiWsSocketDescriptor,
    websocket_proxy_addr: String,
    peer_connection_info: PubkeyConnectionInfo,
    peer_manager: Arc<dyn PeerManager>,
) -> Result<(), MutinyError> {
    if peer_manager
        .get_peer_node_ids()
        .contains(&peer_connection_info.pubkey)
    {
        Ok(())
    } else {
        connect_peer(
            multi_socket,
            websocket_proxy_addr,
            peer_connection_info,
            peer_manager,
        )
        .await
    }
}
pub(crate) async fn connect_peer(
    multi_socket: MultiWsSocketDescriptor,
    websocket_proxy_addr: String,
    peer_connection_info: PubkeyConnectionInfo,
    peer_manager: Arc<dyn PeerManager>,
) -> Result<(), MutinyError> {
    // first make a connection to the node
    debug!("making connection to peer: {:?}", peer_connection_info);
    let (mut descriptor, socket_addr_opt) = match peer_connection_info.connection_type {
        ConnectionType::Tcp(ref t) => {
            let proxy = WsProxy::new(websocket_proxy_addr, peer_connection_info.clone()).await?;
            (
                WsSocketDescriptor::Tcp(WsTcpSocketDescriptor::new(Arc::new(proxy))),
                try_get_net_addr_from_socket(t),
            )
        }
        ConnectionType::Mutiny(_) => (
            WsSocketDescriptor::Mutiny(
                multi_socket
                    .create_new_subsocket(peer_connection_info.pubkey.encode())
                    .await,
            ),
            None,
        ),
    };

    // then give that connection to the peer manager
    let initial_bytes = peer_manager.new_outbound_connection(
        peer_connection_info.pubkey,
        descriptor.clone(),
        socket_addr_opt,
    )?;
    debug!("connected to peer: {:?}", peer_connection_info);

    let sent_bytes = descriptor.send_data(&initial_bytes, true);
    trace!("sent {sent_bytes} to node: {}", peer_connection_info.pubkey);

    // schedule a reader on the connection
    schedule_descriptor_read(descriptor, peer_manager.clone());

    Ok(())
}

fn try_get_net_addr_from_socket(socket_addr: &str) -> Option<NetAddress> {
    socket_addr
        .parse::<SocketAddr>()
        .ok()
        .map(|socket_addr| match socket_addr {
            SocketAddr::V4(sockaddr) => NetAddress::IPv4 {
                addr: sockaddr.ip().octets(),
                port: sockaddr.port(),
            },
            SocketAddr::V6(sockaddr) => NetAddress::IPv6 {
                addr: sockaddr.ip().octets(),
                port: sockaddr.port(),
            },
        })
}

pub(crate) fn create_peer_manager(
    km: Arc<PhantomKeysManager>,
    lightning_msg_handler: MessageHandler,
    logger: Arc<MutinyLogger>,
) -> PeerManagerImpl {
    let now = crate::utils::now().as_secs();
    let mut ephemeral_bytes = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_bytes).expect("Failed to generate entropy");

    PeerManagerImpl::new(
        lightning_msg_handler,
        km.get_node_secret(Recipient::Node)
            .expect("Failed to get node secret"),
        now as u32,
        &ephemeral_bytes,
        logger,
        Arc::new(IgnoringMessageHandler {}),
    )
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, String), MutinyError> {
    let (pubkey, peer_addr_str) = split_peer_connection_string(peer_pubkey_and_ip_addr)?;

    let peer_addr_str_with_port = if peer_addr_str.contains(':') {
        peer_addr_str
    } else {
        format!("{peer_addr_str}:9735")
    };

    Ok((pubkey, peer_addr_str_with_port))
}

pub(crate) fn split_peer_connection_string(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, String), MutinyError> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr.next().ok_or_else(|| {
            error!("incorrectly formatted peer info. Should be formatted as: `pubkey@host:port` but pubkey could not be parsed");
            MutinyError::PeerInfoParseFailed
        })?;
    let peer_addr_str = pubkey_and_addr.next().ok_or_else(|| {
            error!("incorrectly formatted peer info. Should be formatted as: `pubkey@host:port` but host:port part could not be parsed");
            MutinyError::PeerInfoParseFailed
        })?;
    let pubkey = PublicKey::from_str(pubkey).map_err(|e| {
        error!("{}", format!("could not parse peer pubkey: {e:?}"));
        MutinyError::PeerInfoParseFailed
    })?;
    Ok((pubkey, peer_addr_str.to_string()))
}

pub(crate) fn default_user_config() -> UserConfig {
    UserConfig {
        channel_handshake_limits: ChannelHandshakeLimits {
            // lnd's max to_self_delay is 2016, so we want to be compatible.
            their_to_self_delay: 2016,
            ..Default::default()
        },
        channel_handshake_config: ChannelHandshakeConfig {
            minimum_depth: 1,
            announced_channel: false,
            negotiate_scid_privacy: true,
            max_inbound_htlc_value_in_flight_percent_of_channel: 100,
            ..Default::default()
        },
        manually_accept_inbound_channels: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use crate::test::*;
    use std::str::FromStr;

    use crate::node::parse_peer_info;

    use secp256k1::PublicKey;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_parse_peer_info() {
        log!("test parse peer info");

        let pub_key = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let addr = "127.0.0.1:4000";

        let (peer_pubkey, peer_addr) = parse_peer_info(format!("{pub_key}@{addr}")).unwrap();

        assert_eq!(pub_key, peer_pubkey);
        assert_eq!(addr, peer_addr);
    }

    #[test]
    async fn test_parse_peer_info_no_port() {
        log!("test parse peer info with no port");

        let pub_key = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let addr = "127.0.0.1";
        let port = "9735";

        let (peer_pubkey, peer_addr) = parse_peer_info(format!("{pub_key}@{addr}")).unwrap();

        assert_eq!(pub_key, peer_pubkey);
        assert_eq!(format!("{addr}:{port}"), peer_addr);
    }
}
