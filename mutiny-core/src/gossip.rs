use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::Network;
use lightning::routing::gossip::NodeId;
use lightning::util::logger::Logger;
use lightning::util::ser::{ReadableArgs, Writeable};
use lightning::{
    ln::msgs::NodeAnnouncement, routing::scoring::ProbabilisticScoringDecayParameters,
};
use lightning::{log_debug, log_error, log_info, log_warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::MutinyError;
use crate::logging::MutinyLogger;
use crate::node::{NetworkGraph, ProbScorer, RapidGossipSync};
use crate::storage::MutinyStorage;
use crate::utils;

pub(crate) const LN_PEER_METADATA_KEY_PREFIX: &str = "ln_peer/";
pub const GOSSIP_SYNC_TIME_KEY: &str = "last_sync_timestamp";
pub const NETWORK_GRAPH_KEY: &str = "network_graph";
pub const PROB_SCORER_KEY: &str = "prob_scorer";

struct Gossip {
    pub last_sync_timestamp: u32,
    pub network_graph: Arc<NetworkGraph>,
    pub scorer: Option<ProbScorer>,
}

impl Gossip {
    pub fn new(network: Network, logger: Arc<MutinyLogger>) -> Self {
        Self {
            last_sync_timestamp: 0,
            network_graph: Arc::new(NetworkGraph::new(network, logger)),
            scorer: None,
        }
    }
}

async fn get_gossip_data(
    storage: &impl MutinyStorage,
    logger: Arc<MutinyLogger>,
) -> Result<Option<Gossip>, MutinyError> {
    // Get the `last_sync_timestamp`
    let last_sync_timestamp: u32 = match storage.get_data(GOSSIP_SYNC_TIME_KEY)? {
        Some(last_sync_timestamp) => last_sync_timestamp,
        None => return Ok(None),
    };

    // Get the `network_graph`
    let network_graph: Arc<NetworkGraph> = match storage.get_data::<String>(NETWORK_GRAPH_KEY)? {
        Some(network_graph_str) => {
            let network_graph_bytes: Vec<u8> = Vec::from_hex(&network_graph_str)?;
            let mut readable_bytes = lightning::io::Cursor::new(network_graph_bytes);
            Arc::new(NetworkGraph::read(&mut readable_bytes, logger.clone())?)
        }
        None => return Ok(None),
    };

    log_debug!(logger, "Got network graph, getting scorer...");

    // Get the probabilistic scorer
    let scorer = match storage.get_data::<String>(PROB_SCORER_KEY)? {
        Some(prob_scorer_str) => {
            let prob_scorer_bytes: Vec<u8> = Vec::from_hex(&prob_scorer_str)?;
            let mut readable_bytes = lightning::io::Cursor::new(prob_scorer_bytes);
            let params = ProbabilisticScoringDecayParameters::default();
            let args = (params, Arc::clone(&network_graph), Arc::clone(&logger));
            ProbScorer::read(&mut readable_bytes, args)
        }
        None => {
            let gossip = Gossip {
                last_sync_timestamp,
                network_graph,
                scorer: None,
            };
            return Ok(Some(gossip));
        }
    };

    if let Err(e) = scorer.as_ref() {
        log_warn!(
            logger,
            "Could not read probabilistic scorer from database: {e}"
        );
    }

    let gossip = Gossip {
        last_sync_timestamp,
        network_graph,
        scorer: scorer.ok(),
    };

    Ok(Some(gossip))
}

fn write_gossip_data(
    storage: &impl MutinyStorage,
    last_sync_timestamp: u32,
    network_graph: &NetworkGraph,
) -> Result<(), MutinyError> {
    // Save the last sync timestamp
    storage.set_data(GOSSIP_SYNC_TIME_KEY, last_sync_timestamp)?;

    // Save the network graph
    storage.set_data(NETWORK_GRAPH_KEY, network_graph.encode().to_hex())?;

    Ok(())
}

pub async fn get_gossip_sync(
    storage: &impl MutinyStorage,
    user_rgs_url: Option<String>,
    network: Network,
    logger: Arc<MutinyLogger>,
) -> Result<(RapidGossipSync, ProbScorer), MutinyError> {
    // if we error out, we just use the default gossip data
    let gossip_data = match get_gossip_data(storage, logger.clone()).await {
        Ok(Some(gossip_data)) => gossip_data,
        Ok(None) => Gossip::new(network, logger.clone()),
        Err(e) => {
            log_error!(
                logger,
                "Error getting gossip data from storage: {e}, re-syncing gossip..."
            );
            Gossip::new(network, logger.clone())
        }
    };

    log_debug!(
        &logger,
        "Previous gossip sync timestamp: {}",
        gossip_data.last_sync_timestamp
    );

    // get network graph
    let gossip_sync = RapidGossipSync::new(gossip_data.network_graph.clone(), logger.clone());

    let prob_scorer = match gossip_data.scorer {
        Some(scorer) => scorer,
        None => {
            let params = ProbabilisticScoringDecayParameters::default();
            ProbScorer::new(params, gossip_data.network_graph.clone(), logger.clone())
        }
    };

    if let Some(rgs_url) = get_rgs_url(network, user_rgs_url, Some(gossip_data.last_sync_timestamp))
    {
        log_info!(&logger, "RGS URL: {}", rgs_url);

        let now = utils::now().as_secs();
        let fetch_result = fetch_updated_gossip(
            rgs_url,
            now,
            gossip_data.last_sync_timestamp,
            &gossip_sync,
            storage,
            &logger,
        )
        .await;

        if fetch_result.is_err() {
            log_warn!(
                logger,
                "Failed to fetch updated gossip, using default gossip data"
            );
        }
    }

    Ok((gossip_sync, prob_scorer))
}

async fn fetch_updated_gossip(
    rgs_url: String,
    now: u64,
    last_sync_timestamp: u32,
    gossip_sync: &RapidGossipSync,
    storage: &impl MutinyStorage,
    logger: &MutinyLogger,
) -> Result<(), MutinyError> {
    let http_client = Client::builder()
        .build()
        .map_err(|_| MutinyError::RapidGossipSyncError)?;
    let rgs_response = http_client
        .get(rgs_url)
        .send()
        .await
        .map_err(|_| MutinyError::RapidGossipSyncError)?;

    let rgs_data = rgs_response
        .bytes()
        .await
        .map_err(|_| MutinyError::RapidGossipSyncError)?
        .to_vec();

    let new_last_sync_timestamp_result =
        gossip_sync.update_network_graph_no_std(&rgs_data, Some(now))?;

    log_info!(
        logger,
        "RGS sync result: {}",
        new_last_sync_timestamp_result
    );

    // save the network graph if has been updated
    if new_last_sync_timestamp_result != last_sync_timestamp {
        write_gossip_data(
            storage,
            new_last_sync_timestamp_result,
            gossip_sync.network_graph(),
        )?;
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LnPeerMetadata {
    /// The node's network address to connect to
    pub connection_string: Option<String>,
    /// The node's alias given from the node announcement
    pub alias: Option<String>,
    /// The node's color given from the node announcement
    pub color: Option<String>,
    /// The label set by the user for this node
    pub label: Option<String>,
    /// The timestamp of when this information was last updated
    pub timestamp: Option<u32>,
    /// Our nodes' uuids that are connected to this node
    #[serde(default)]
    pub nodes: Vec<String>,
}

impl LnPeerMetadata {
    pub(crate) fn with_connection_string(self, connection_string: String) -> Self {
        Self {
            connection_string: Some(connection_string),
            ..self
        }
    }

    pub(crate) fn with_node(&self, node: String) -> Self {
        let mut nodes = self.nodes.clone();

        if !nodes.contains(&node) {
            nodes.push(node);
            nodes.sort();
        }

        Self {
            nodes,
            ..self.clone()
        }
    }

    pub(crate) fn with_label(&self, label: Option<String>) -> Self {
        Self {
            label,
            ..self.clone()
        }
    }

    pub(crate) fn merge_opt(&self, other: &Option<LnPeerMetadata>) -> LnPeerMetadata {
        match other {
            Some(other) => self.merge(other),
            None => self.clone(),
        }
    }

    pub(crate) fn merge(&self, other: &LnPeerMetadata) -> LnPeerMetadata {
        let (primary, secondary) = if self.timestamp > other.timestamp {
            (self.clone(), other.clone())
        } else {
            (other.clone(), self.clone())
        };

        // combine nodes from both
        let mut nodes: Vec<String> = primary
            .nodes
            .into_iter()
            .chain(secondary.nodes.into_iter())
            .collect();

        // remove duplicates
        nodes.sort();
        nodes.dedup();

        Self {
            connection_string: primary.connection_string.or(secondary.connection_string),
            alias: primary.alias.or(secondary.alias),
            color: primary.color.or(secondary.color),
            label: primary.label.or(secondary.label),
            timestamp: primary.timestamp.or(secondary.timestamp),
            nodes,
        }
    }
}

impl From<NodeAnnouncement> for LnPeerMetadata {
    fn from(value: NodeAnnouncement) -> Self {
        Self {
            connection_string: None, // todo get from addresses
            alias: Some(value.contents.alias.to_string()),
            color: Some(value.contents.rgb.to_hex()),
            label: None,
            timestamp: Some(value.contents.timestamp),
            nodes: vec![],
        }
    }
}

pub(crate) fn read_peer_info(
    storage: &impl MutinyStorage,
    node_id: &NodeId,
) -> Result<Option<LnPeerMetadata>, MutinyError> {
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");
    storage.get_data(key)
}

pub(crate) fn get_all_peers(
    storage: &impl MutinyStorage,
) -> Result<HashMap<NodeId, LnPeerMetadata>, MutinyError> {
    let mut peers = HashMap::new();

    let all: HashMap<String, LnPeerMetadata> = storage.scan(LN_PEER_METADATA_KEY_PREFIX, None)?;
    for (key, value) in all {
        // remove the prefix from the key
        let key = key.replace(LN_PEER_METADATA_KEY_PREFIX, "");
        let node_id = NodeId::from_str(&key)?;
        peers.insert(node_id, value);
    }
    Ok(peers)
}

pub(crate) fn save_peer_connection_info(
    storage: &impl MutinyStorage,
    our_node_id: &str,
    node_id: &NodeId,
    connection_string: &str,
    label: Option<String>,
) -> Result<(), MutinyError> {
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");

    let current: Option<LnPeerMetadata> = storage.get_data(&key)?;

    // If there is already some metadata, we add the connection string to it
    // Otherwise we create a new metadata with the connection string
    let new_info = match current {
        Some(current) => current
            .with_connection_string(connection_string.to_string())
            .with_node(our_node_id.to_string()),
        None => LnPeerMetadata {
            connection_string: Some(connection_string.to_string()),
            label,
            timestamp: Some(utils::now().as_secs() as u32),
            nodes: vec![our_node_id.to_string()],
            ..Default::default()
        },
    };

    storage.set_data(key, new_info)?;
    Ok(())
}

pub(crate) fn set_peer_label(
    storage: &impl MutinyStorage,
    node_id: &NodeId,
    label: Option<String>,
) -> Result<(), MutinyError> {
    // We filter out empty labels
    let label = label.filter(|l| !l.is_empty());
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");

    let current: Option<LnPeerMetadata> = storage.get_data(&key)?;

    // If there is already some metadata, we add the label to it
    // Otherwise we create a new metadata with the label
    let new_info = match current {
        Some(current) => current.with_label(label),
        None => LnPeerMetadata {
            label,
            timestamp: Some(utils::now().as_secs() as u32),
            ..Default::default()
        },
    };

    storage.set_data(key, new_info)?;
    Ok(())
}

pub(crate) fn delete_peer_info(
    storage: &impl MutinyStorage,
    uuid: &str,
    node_id: &NodeId,
) -> Result<(), MutinyError> {
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");

    let current: Option<LnPeerMetadata> = storage.get_data(&key)?;

    if let Some(mut current) = current {
        current.nodes.retain(|n| n != uuid);
        if current.nodes.is_empty() {
            storage.delete(&[key])?;
        } else {
            storage.set_data(key, current)?;
        }
    }

    Ok(())
}

pub(crate) fn save_ln_peer_info(
    storage: &impl MutinyStorage,
    node_id: &NodeId,
    info: &LnPeerMetadata,
) -> Result<(), MutinyError> {
    let key = format!("{LN_PEER_METADATA_KEY_PREFIX}{node_id}");

    let current: Option<LnPeerMetadata> = storage.get_data(&key)?;

    let new_info = info.merge_opt(&current);

    // if the new info is different than the current info, we should to save it
    if !current.is_some_and(|c| c == new_info) {
        storage.set_data(key, new_info)?;
    }

    Ok(())
}

pub(crate) fn get_rgs_url(
    network: Network,
    user_provided_url: Option<String>,
    last_sync_time: Option<u32>,
) -> Option<String> {
    let last_sync_time = last_sync_time.unwrap_or(0);
    if let Some(url) = user_provided_url.filter(|url| !url.is_empty()) {
        let url = url.strip_suffix('/').unwrap_or(&url);
        Some(format!("{url}/{last_sync_time}"))
    } else {
        match network {
            Network::Bitcoin => Some(format!(
                "https://rapidsync.lightningdevkit.org/snapshot/{last_sync_time}"
            )),
            Network::Testnet => Some(format!(
                "https://rapidsync.lightningdevkit.org/testnet/snapshot/{last_sync_time}"
            )),
            Network::Signet => Some(format!(
                "https://rgs.mutinynet.com/snapshot/{last_sync_time}"
            )),
            Network::Regtest => None,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::storage::MemoryStorage;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use uuid::Uuid;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    fn dummy_node_id() -> NodeId {
        let secp = Secp256k1::new();
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).unwrap();
        let secret_key = SecretKey::from_slice(&entropy).unwrap();
        let pubkey = secret_key.public_key(&secp);
        NodeId::from_pubkey(&pubkey)
    }

    fn dummy_peer_info() -> (NodeId, LnPeerMetadata) {
        let node_id = dummy_node_id();
        let uuid = Uuid::new_v4().to_string();
        let data = LnPeerMetadata {
            connection_string: Some("example.com:9735".to_string()),
            alias: Some("test alias".to_string()),
            color: Some("123456".to_string()),
            label: Some("test label".to_string()),
            timestamp: Some(utils::now().as_secs() as u32),
            nodes: vec![uuid],
        };

        (node_id, data)
    }

    #[test]
    fn test_merge_peer_info() {
        let no_timestamp = LnPeerMetadata {
            alias: Some("none".to_string()),
            timestamp: None,
            ..Default::default()
        };
        let max_timestamp = LnPeerMetadata {
            alias: Some("max".to_string()),
            timestamp: Some(u32::MAX),
            ..Default::default()
        };
        let min_timestamp = LnPeerMetadata {
            alias: Some("min".to_string()),
            timestamp: Some(u32::MIN),
            ..Default::default()
        };

        assert_eq!(no_timestamp.merge(&max_timestamp), max_timestamp);
        assert_eq!(no_timestamp.merge(&min_timestamp), min_timestamp);
        assert_eq!(max_timestamp.merge(&min_timestamp), max_timestamp);
    }

    #[test]
    // hack to disable this test
    #[cfg(feature = "ignored_tests")]
    async fn test_gossip() {
        crate::test_utils::log!("test RGS sync");
        let storage = MemoryStorage::default();

        let logger = Arc::new(MutinyLogger::default());
        let _gossip_sync = get_gossip_sync(&storage, None, Network::Regtest, logger.clone())
            .await
            .unwrap();

        let data = get_gossip_data(&storage, logger).await.unwrap();

        assert!(data.is_some());
        assert!(data.unwrap().last_sync_timestamp > 0);
    }

    #[test]
    fn test_peer_info() {
        let storage = MemoryStorage::default();
        let (node_id, data) = dummy_peer_info();

        save_ln_peer_info(&storage, &node_id, &data).unwrap();

        let read = read_peer_info(&storage, &node_id).unwrap();
        let all = get_all_peers(&storage).unwrap();

        assert!(read.is_some());
        assert_eq!(read.unwrap(), data);
        assert_eq!(all.len(), 1);
        assert_eq!(*all.get(&node_id).unwrap(), data);

        delete_peer_info(&storage, data.nodes.first().unwrap(), &node_id).unwrap();

        let read = read_peer_info(&storage, &node_id).unwrap();

        assert!(read.is_none());
    }

    #[test]
    fn test_delete_label() {
        let storage = MemoryStorage::default();

        let (node_id, data) = dummy_peer_info();

        save_ln_peer_info(&storage, &node_id, &data).unwrap();

        // remove the label
        set_peer_label(&storage, &node_id, None).unwrap();

        let read = read_peer_info(&storage, &node_id).unwrap();

        let expected = LnPeerMetadata {
            label: None,
            ..data
        };

        assert!(read.is_some());
        assert_eq!(read.unwrap(), expected);
    }
}
