use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use async_lock::RwLock;
use bitcoin::hashes::hex::FromHex;
use bitcoin::key::Parity;
use bitcoin::secp256k1::ThirtyTwoByteHash;
use bitcoin::{bip32::ExtendedPrivKey, secp256k1::Secp256k1};
use fedimint_core::api::InviteCode;
use fedimint_core::config::FederationId;
use futures::{pin_mut, select, FutureExt};
use lightning::util::logger::Logger;
use lightning::{log_debug, log_error, log_info, log_warn};
use lightning_invoice::Bolt11Invoice;
use nostr::secp256k1::SecretKey;
use nostr::{nips::nip04::decrypt, Event, JsonUtil, Keys, RelayMessage, Tag, ToBech32};
use nostr::{prelude::decrypt_received_private_zap_message, EventBuilder};
use nostr::{Filter, Kind, Timestamp};
use nostr_sdk::{Client, RelayPoolNotification};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use tbs::unblind_signature;
use url::Url;

use crate::event::{HTLCStatus, MillisatAmount, PaymentInfo};
use crate::federation::FedimintClient;
use crate::labels::LabelStorage;
use crate::nostr::RELAYS;
use crate::storage::{persist_payment_info, LAST_HERMES_SYNC_TIME_KEY};
use crate::{
    blindauth::{BlindAuthClient, SignedToken},
    error::MutinyError,
    federation::{FederationClient, FederationIdentity},
    logging::MutinyLogger,
    nostr::{derive_nostr_key, HERMES_CHAIN_INDEX, SERVICE_ACCOUNT_INDEX},
    storage::MutinyStorage,
    utils, PrivacyLevel,
};

const HERMES_SERVICE_ID: u32 = 1;
#[allow(dead_code)]
const HERMES_FREE_PLAN_ID: u32 = 1;
const HERMES_PAID_PLAN_ID: u32 = 2;

const REGISTRATION_CHECK_EVENT_KIND: Kind = Kind::Custom(93_186);
const NEW_FEDERATION_EVENT_KIND: Kind = Kind::Custom(93_187);
const DISABLE_ZAPS_EVENT_KIND: Kind = Kind::Custom(93_188);

#[derive(Deserialize, Serialize)]
pub struct RegisterRequest {
    pub name: Option<String>,
    pub pubkey: String,
    pub federation_invite_code: String,
    pub msg: tbs::Message,
    pub sig: tbs::Signature,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterResponse {
    pub name: String,
}

pub struct HermesClient<S: MutinyStorage> {
    pub(crate) dm_key: Keys,
    pub(crate) claim_key: SecretKey,
    pub public_key: nostr::PublicKey,
    pub client: Client,
    http_client: reqwest::Client,
    pub(crate) federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
    blind_auth: Arc<BlindAuthClient<S>>,
    base_url: String,
    // bool represents whether or not it was successfully checked
    current_address: Arc<RwLock<(Option<String>, bool)>>,
    storage: S,
    pub logger: Arc<MutinyLogger>,
    pub stop: Arc<AtomicBool>,
}

impl<S: MutinyStorage> HermesClient<S> {
    pub async fn new(
        xprivkey: ExtendedPrivKey,
        base_url: String,
        federations: Arc<RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>>,
        blind_auth: Arc<BlindAuthClient<S>>,
        storage: &S,
        logger: Arc<MutinyLogger>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self, MutinyError> {
        let keys = derive_nostr_key(
            &Secp256k1::new(),
            xprivkey,
            SERVICE_ACCOUNT_INDEX,
            Some(HERMES_CHAIN_INDEX),
            None,
        )?;
        let public_key = keys.public_key();
        let client = Client::new(&keys);

        client
            .add_relays(
                // we are listening only, so no need to connect to blastr
                RELAYS
                    .into_iter()
                    .filter(|r| *r != "wss://nostr.mutinywallet.com"),
            )
            .await
            .expect("Failed to add relays");

        // we use even parity on hermes side, need to check if we need to negate
        let sec = keys.secret_key().expect("must have");
        let claim_key = if sec.x_only_public_key(&Secp256k1::new()).1 == Parity::Even {
            sec.clone()
        } else {
            sec.negate().into()
        };

        Ok(Self {
            dm_key: keys,
            claim_key: *claim_key,
            public_key,
            client,
            http_client: reqwest::Client::new(),
            base_url,
            federations,
            blind_auth,
            current_address: Arc::new(RwLock::new((None, false))),
            storage: storage.clone(),
            logger,
            stop,
        })
    }

    /// Starts the hermes background checker
    /// This should only error if there's an initial unrecoverable error
    /// Otherwise it will loop in the background until a stop signal
    pub async fn start(&self, profile_key: Option<Keys>) -> Result<(), MutinyError> {
        // if we haven't synced before, use now and save to storage
        let last_sync_time = self.storage.get_dm_sync_time(true)?;
        let time_stamp = match last_sync_time {
            None => {
                let now = Timestamp::from(0);
                self.storage.set_dm_sync_time(now.as_u64(), true)?;
                now
            }
            Some(time) => Timestamp::from(time + 1), // add one so we get only new events
        };

        // check to see if we currently have an address
        let logger_check_clone = self.logger.clone();
        let stop_check_clone = self.stop.clone();
        let http_client_check_clone = self.http_client.clone();
        let nostr_client_check_clone = self.client.clone();
        let base_url_check_clone = self.base_url.clone();
        let current_address_check_clone = self.current_address.clone();
        let first_federation = self.get_first_federation().await.clone();
        utils::spawn(async move {
            let mut count = 1;
            loop {
                if stop_check_clone.load(Ordering::Relaxed) {
                    break;
                };

                match check_hermes_registration_info(
                    &http_client_check_clone,
                    &base_url_check_clone,
                    nostr_client_check_clone.clone(),
                )
                .await
                {
                    Ok(o) => {
                        {
                            let mut c = current_address_check_clone.write().await;
                            log_info!(
                                logger_check_clone,
                                "checked lightning address: {:?}",
                                o.name
                            );
                            *c = (o.name.clone(), true);
                        }

                        // check that federation is still the same
                        if let Some(f) = first_federation {
                            // if a registered federation exists and is what we have and zaps are enabled
                            // then there is no reason to update
                            if o.federation_id.is_some_and(|id| id == f.federation_id)
                                && !o.disabled_zaps
                            {
                                break;
                            }

                            // user has a federation registered but is different than current
                            // so we should update it
                            log_info!(
                                logger_check_clone,
                                "registered federation is different, changing {:?} to {:?}",
                                o.federation_id,
                                f.federation_id
                            );
                            match change_federation_info(
                                &http_client_check_clone,
                                &base_url_check_clone,
                                nostr_client_check_clone,
                                current_address_check_clone,
                                &f.invite_code,
                                &logger_check_clone,
                            )
                            .await
                            {
                                Ok(_) => {
                                    log_debug!(
                                        logger_check_clone,
                                        "changed federation successfully"
                                    );
                                }
                                Err(e) => {
                                    log_error!(
                                        logger_check_clone,
                                        "could not change the federation: {e}"
                                    );
                                }
                            }
                        } else {
                            // handle the case where the user no longer has a federation
                            // if user is already disabled, no need to call again
                            if !o.disabled_zaps {
                                log_info!(
                                    logger_check_clone,
                                    "user no longer has a federation, disabling zaps"
                                );
                                match disable_zaps(
                                    &http_client_check_clone,
                                    &base_url_check_clone,
                                    nostr_client_check_clone,
                                    current_address_check_clone,
                                    &logger_check_clone,
                                )
                                .await
                                {
                                    Ok(_) => {
                                        log_debug!(
                                            logger_check_clone,
                                            "disabled zaps successfully"
                                        );
                                    }
                                    Err(e) => {
                                        log_error!(
                                            logger_check_clone,
                                            "could not disable zaps: {e}"
                                        );
                                    }
                                }
                            }
                        }

                        break;
                    }
                    Err(e) => {
                        log_error!(logger_check_clone, "error checking lightning address: {e}");
                    }
                };

                // exponential backoff
                let sleep_time = std::cmp::min(1_000 * (2_i32.pow(count)), 60_000);
                utils::sleep(sleep_time).await;
                count += 1;
            }
        });

        let logger = self.logger.clone();
        let stop = self.stop.clone();
        let client = self.client.clone();
        let public_key = self.public_key;
        let claim_key = self.claim_key;
        let storage = self.storage.clone();
        let dm_key = self.dm_key.clone();
        let federations = self.federations.clone();
        utils::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                };

                log_info!(logger, "Starting Hermes DM listener for key {public_key}");

                let received_dm_filter = Filter::new()
                    .kind(Kind::EncryptedDirectMessage)
                    .pubkey(public_key)
                    .since(time_stamp);

                client.connect().await;

                client.subscribe(vec![received_dm_filter], None).await;

                let mut has_received_eose = false;
                let mut batch_notifications: Vec<(EcashNotification, Timestamp)> = Vec::new();

                let mut notifications = client.notifications();

                loop {
                    let read_fut = notifications.recv().fuse();
                    let delay_fut = Box::pin(utils::sleep(1_000)).fuse();

                    pin_mut!(read_fut, delay_fut);
                    select! {
                        notification = read_fut => {
                            match notification {
                                Ok(RelayPoolNotification::Event { event, .. }) => {
                                    if event.verify().is_ok() {
                                        match event.kind {
                                            Kind::EncryptedDirectMessage => {
                                                match decrypt_ecash_notification(&dm_key, event.pubkey, &event.content) {
                                                    Ok(notification) => {
                                                        // if we have received an EOSE, we should immediately handle the notification
                                                        // otherwise we should wait until we have received an EOSE so we can do the initial batch
                                                        if has_received_eose {
                                                            if let Err(e) = handle_ecash_notification(notification, event.created_at, &federations, &storage, &claim_key, profile_key.as_ref(), &logger).await {
                                                                log_error!(logger, "Error handling ecash notification: {e}");
                                                            } else if let Err(e) = storage.set_dm_sync_time(event.created_at.as_u64(), true) { // save the last sync time after processing the notification
                                                                log_error!(logger, "Error saving last sync time: {e}");
                                                            }
                                                        } else {
                                                            log_debug!(logger, "Received ecash notification, adding to batch");
                                                            batch_notifications.push((notification, event.created_at));
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log_error!(logger, "Error decrypting DM: {e}");
                                                    }
                                                }
                                            }
                                            kind => log_warn!(logger, "Received unexpected note of kind {kind}")
                                        }
                                    }
                                },
                                Ok(RelayPoolNotification::Message { message, .. }) => {
                                    // if we receive an EOSE, we have received all the notifications from the relay
                                    // and can now handle the batch
                                    if let RelayMessage::EndOfStoredEvents(_) = message {
                                        has_received_eose = true;
                                        if !batch_notifications.is_empty() {
                                            let mut max_created_at: Option<Timestamp> = None;
                                            for (notification, created_at) in batch_notifications.drain(..) {
                                                if let Err(e) = handle_ecash_notification(notification, created_at, &federations, &storage, &claim_key, profile_key.as_ref(), &logger).await {
                                                    log_error!(logger, "Error handling ecash notification: {e}");
                                                } else if max_created_at.is_none() || max_created_at.is_some_and(|x| x < created_at) {
                                                    max_created_at = Some(created_at);
                                                }
                                            }

                                            // save the last sync time after the batch
                                            if let Some(max_created_at) = max_created_at {
                                                if let Err(e) = storage.set_dm_sync_time(max_created_at.as_u64(), true) {
                                                    log_error!(logger, "Error saving last sync time: {e}");
                                                }
                                            }
                                        }
                                    }
                                },
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
                    }
                }

                if let Err(e) = client.disconnect().await {
                    log_warn!(logger, "Error disconnecting from relays: {e}");
                }
            }
        });

        Ok(())
    }

    /// Resyncs the hermes client by subscribing to older DMs.
    pub async fn resync(&self) -> Result<(), MutinyError> {
        // reset last sync time to zero
        self.storage
            .set_data(LAST_HERMES_SYNC_TIME_KEY.to_string(), 0, None)?;

        let received_dm_filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.public_key)
            .since(Timestamp::from(0));

        // subscribe to older DMs to resync
        self.client.connect().await;
        self.client.subscribe(vec![received_dm_filter], None).await;

        // the rest should happen in the background thread that handles the events

        Ok(())
    }

    pub async fn change_federation_info(
        &self,
        invite_code: &InviteCode,
    ) -> Result<(), MutinyError> {
        change_federation_info(
            &self.http_client,
            &self.base_url,
            self.client.clone(),
            self.current_address.clone(),
            invite_code,
            &self.logger,
        )
        .await
    }

    pub async fn disable_zaps(&self) -> Result<(), MutinyError> {
        disable_zaps(
            &self.http_client,
            &self.base_url,
            self.client.clone(),
            self.current_address.clone(),
            &self.logger,
        )
        .await
    }

    pub async fn check_available_name(&self, name: String) -> Result<bool, MutinyError> {
        check_name_request(&self.http_client, &self.base_url, name).await
    }

    pub async fn reserve_name(&self, name: String) -> Result<(), MutinyError> {
        // check that we have a name token available
        let available_tokens = self.blind_auth.available_tokens().await;
        let available_paid_token =
            match find_hermes_token(&available_tokens, HERMES_SERVICE_ID, HERMES_PAID_PLAN_ID) {
                Some(t) => t,
                None => {
                    log_error!(
                        self.logger,
                        "No available paid token for Hermes, current tokens: {}",
                        available_tokens.len()
                    );
                    return Err(MutinyError::NotFound);
                }
            };

        // check that we have a federation added and get it's id/invite code
        let federation_identity = match self.get_first_federation().await {
            Some(f) => f,
            None => return Err(MutinyError::FederationRequired),
        };

        // do the unblinding
        let (nonce, blinding_key) = self
            .blind_auth
            .get_unblinded_info_from_token(available_paid_token);
        let unblinded_sig = unblind_signature(blinding_key, available_paid_token.blind_sig);

        // send the register request
        let req = RegisterRequest {
            name: Some(name.clone()),
            pubkey: self.public_key.to_string(),
            federation_invite_code: federation_identity.invite_code.to_string(),
            msg: nonce.to_message(),
            sig: unblinded_sig,
        };
        register_name(&self.http_client.clone(), &self.base_url, req).await?;

        {
            let mut c = self.current_address.write().await;
            log_info!(
                self.logger,
                "registered lightning address: {}",
                name.clone()
            );
            *c = (Some(name), true);
        }

        // Mark the token as spent successfully
        self.blind_auth.used_token(available_paid_token).await?;

        Ok(())
    }

    pub async fn check_username(&self) -> Result<Option<String>, MutinyError> {
        match self.current_address.read().await.clone() {
            (None, false) => Err(MutinyError::ConnectionFailed),
            (Some(n), true) => Ok(Some(n)),
            (None, true) => Ok(None),
            _ => {
                unreachable!("can't have some and false")
            }
        }
    }

    async fn get_first_federation(&self) -> Option<FederationIdentity> {
        let federations = self.federations.read().await;
        match federations.iter().next() {
            Some((_, n)) => Some(n.get_mutiny_federation_identity().await),
            None => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChangeFederationRequest {
    pub name: Option<String>,
    pub federation_id: Option<FederationId>,
}

async fn change_federation_info(
    http_client: &reqwest::Client,
    base_url: &str,
    nostr_client: Client,
    current_address: Arc<RwLock<(Option<String>, bool)>>,
    invite_code: &InviteCode,
    logger: &MutinyLogger,
) -> Result<(), MutinyError> {
    // make sure name is registered already
    if current_address.read().await.0.is_none() {
        log_warn!(
            logger,
            "can't change federation when the address is unknown"
        );
        return Ok(());
    }

    // create nostr event
    let signer = nostr_client.signer().await?;
    let event_builder = EventBuilder::new(NEW_FEDERATION_EVENT_KIND, invite_code.to_string(), []);
    let event = signer.sign_event_builder(event_builder).await?;

    // send request
    let url = Url::parse(&format!("{}/v1/change-federation", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let request = http_client.request(Method::POST, url).json(&event);
    let _ = utils::fetch_with_timeout(
        http_client,
        request.build().map_err(|_| MutinyError::ConnectionFailed)?,
    )
    .await
    .map_err(|_| MutinyError::ConnectionFailed)?;

    log_info!(logger, "changed federation info to current federation");

    Ok(())
}

async fn disable_zaps(
    http_client: &reqwest::Client,
    base_url: &str,
    nostr_client: Client,
    current_address: Arc<RwLock<(Option<String>, bool)>>,
    logger: &MutinyLogger,
) -> Result<(), MutinyError> {
    // make sure name is registered already
    if current_address.read().await.0.is_none() {
        log_warn!(logger, "can't disable zaps when the address is unknown");
        return Ok(());
    }

    // create nostr event
    let signer = nostr_client.signer().await?;
    let event_builder = EventBuilder::new(DISABLE_ZAPS_EVENT_KIND, "", []);
    let event = signer.sign_event_builder(event_builder).await?;

    // send request
    let url = Url::parse(&format!("{}/v1/disable-zaps", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let request = http_client.request(Method::POST, url).json(&event);
    let _ = utils::fetch_with_timeout(
        http_client,
        request.build().map_err(|_| MutinyError::ConnectionFailed)?,
    )
    .await
    .map_err(|_| MutinyError::ConnectionFailed)?;

    log_info!(logger, "disabled zaps for the user");

    Ok(())
}

fn find_hermes_token(
    tokens: &[SignedToken],
    service_id: u32,
    plan_id: u32,
) -> Option<&SignedToken> {
    tokens
        .iter()
        .find(|token| token.service_id == service_id && token.plan_id == plan_id)
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RegistrationInfo {
    pub name: Option<String>,
    pub federation_id: Option<FederationId>,
    pub disabled_zaps: bool,
}

async fn check_hermes_registration_info(
    http_client: &reqwest::Client,
    base_url: &str,
    nostr_client: Client,
) -> Result<RegistrationInfo, MutinyError> {
    // create nostr event
    let signer = nostr_client.signer().await?;
    let event_builder = EventBuilder::new(REGISTRATION_CHECK_EVENT_KIND, "", []);
    let event = signer.sign_event_builder(event_builder).await?;

    // send request
    let url = Url::parse(&format!("{}/v1/check-registration", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let request = http_client.request(Method::POST, url).json(&event);
    let res = utils::fetch_with_timeout(
        http_client,
        request.build().map_err(|_| MutinyError::ConnectionFailed)?,
    )
    .await?
    .json::<RegistrationInfo>()
    .await
    .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(res)
}

async fn check_name_request(
    http_client: &reqwest::Client,
    base_url: &str,
    name: String,
) -> Result<bool, MutinyError> {
    let url = Url::parse(&format!("{}/v1/check-username/{name}", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let request = http_client.request(Method::GET, url);

    let res = utils::fetch_with_timeout(
        http_client,
        request.build().map_err(|_| MutinyError::ConnectionFailed)?,
    )
    .await?
    .json::<bool>()
    .await
    .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(res)
}

async fn register_name(
    http_client: &reqwest::Client,
    base_url: &str,
    req: RegisterRequest,
) -> Result<RegisterResponse, MutinyError> {
    let url = Url::parse(&format!("{}/v1/register", base_url))
        .map_err(|_| MutinyError::ConnectionFailed)?;
    let request = http_client.request(Method::POST, url).json(&req);

    let res = utils::fetch_with_timeout(
        http_client,
        request.build().map_err(|_| MutinyError::ConnectionFailed)?,
    )
    .await?
    .json::<RegisterResponse>()
    .await
    .map_err(|_| MutinyError::ConnectionFailed)?;

    Ok(res)
}

/// Decrypts a DM using the primary key
fn decrypt_ecash_notification(
    dm_key: &Keys,
    pubkey: nostr::PublicKey,
    message: &str,
) -> Result<EcashNotification, MutinyError> {
    // decrypt the dm first
    let secret = dm_key.secret_key().expect("must have");
    let decrypted = decrypt(secret, &pubkey, message)?;
    // parse the dm into an ecash notification
    let notification = serde_json::from_str(&decrypted)?;
    Ok(notification)
}

/// What the hermes client expects to receive from a DM
#[derive(Debug, Clone, Deserialize, Serialize)]
struct EcashNotification {
    /// Amount of ecash received in msats
    pub amount: u64,
    /// Tweak we should use to claim the ecash
    pub tweak_index: u64,
    /// Federation id that the ecash is for
    pub federation_id: FederationId,
    /// The zap request that came along with this payment,
    /// useful for tagging the payment to a contact
    pub zap_request: Option<String>,
    /// The bolt11 invoice for the payment
    pub bolt11: Bolt11Invoice,
    /// The preimage for the bolt11 invoice
    pub preimage: String,
}

async fn claim_ecash_notification<S: MutinyStorage>(
    notification: EcashNotification,
    created_at: Timestamp,
    federation: &impl FedimintClient,
    storage: &S,
    claim_key: &SecretKey,
    profile_key: Option<&Keys>,
    logger: &MutinyLogger,
) -> anyhow::Result<Option<PaymentInfo>> {
    match federation
        .claim_external_receive(claim_key, vec![notification.tweak_index])
        .await
    {
        Ok(_) => {
            log_info!(
                logger,
                "Claimed external receive for {} msats!",
                notification.amount
            );

            let (privacy_level, msg, npub) = match notification.zap_request {
                None => (PrivacyLevel::NotAvailable, None, None),
                Some(zap_req) => {
                    let zap_req = Event::from_json(zap_req)?;
                    // handle private/anon zaps
                    let anon = zap_req.iter_tags().find_map(|tag| {
                        if let Tag::Anon { msg } = tag {
                            if msg.is_some() {
                                // an Anon tag with a message is a private zap
                                // try to decrypt the message and use that as the message
                                Some(handle_private_zap(&zap_req, profile_key, logger))
                            } else {
                                // an Anon tag with no message is an anonymous zap
                                // the content of the zap is the message
                                Some((PrivacyLevel::Anonymous, Some(zap_req.content.clone()), None))
                            }
                        } else {
                            None
                        }
                    });

                    // handled the anon tag, if there wasn't one, it is a public zap
                    anon.unwrap_or((
                        PrivacyLevel::Public,
                        Some(zap_req.content.clone()),
                        Some(zap_req.pubkey),
                    ))
                }
            };

            // create activity item
            let payment_hash = notification.bolt11.payment_hash().into_32();
            let preimage = FromHex::from_hex(&notification.preimage).ok();
            let info = PaymentInfo {
                preimage,
                secret: Some(notification.bolt11.payment_secret().0),
                status: HTLCStatus::Succeeded,
                amt_msat: MillisatAmount(Some(notification.amount)),
                fee_paid_msat: None,
                payee_pubkey: Some(notification.bolt11.recover_payee_pub_key()),
                bolt11: Some(notification.bolt11.clone()),
                privacy_level,
                // use the notification event's created_at as last update so we can properly sort by time
                last_update: created_at.as_u64(),
            };
            persist_payment_info(storage, &payment_hash, &info, true)?;

            // tag the invoice if we can
            let mut tags = Vec::with_capacity(2);

            // try to tag by contact by npub, otherwise tag by pubkey
            if let Some(npub) = npub {
                if let Some((id, _)) = storage.get_contact_for_npub(npub)? {
                    tags.push(id);
                } else {
                    tags.push(npub.to_bech32().expect("must be valid"));
                }
            }

            // add message tag if we have one
            if let Some(msg) = msg.filter(|m| !m.is_empty()) {
                tags.push(msg);
            }

            // save the tags if we have any
            if !tags.is_empty() {
                storage.set_invoice_labels(notification.bolt11, tags)?;
            }

            return Ok(Some(info));
        }
        Err(e) => log_error!(logger, "Error claiming external receive: {e}"),
    }

    Ok(None)
}

/// Attempts to claim the ecash, if successful, saves the payment info
async fn handle_ecash_notification<S: MutinyStorage>(
    notification: EcashNotification,
    created_at: Timestamp,
    federations: &RwLock<HashMap<FederationId, Arc<FederationClient<S>>>>,
    storage: &S,
    claim_key: &SecretKey,
    profile_key: Option<&Keys>,
    logger: &MutinyLogger,
) -> anyhow::Result<()> {
    log_info!(
        logger,
        "Received ecash notification for {} msats!",
        notification.amount
    );

    if let Some(federation) = federations.read().await.get(&notification.federation_id) {
        claim_ecash_notification(
            notification,
            created_at,
            federation.as_ref(),
            storage,
            claim_key,
            profile_key,
            logger,
        )
        .await?;
    } else {
        log_warn!(
            logger,
            "Received DM for unknown federation {}, discarding...",
            notification.federation_id
        );
    }

    Ok(())
}

fn handle_private_zap(
    zap_req: &Event,
    profile_key: Option<&Keys>,
    logger: &MutinyLogger,
) -> (PrivacyLevel, Option<String>, Option<nostr::PublicKey>) {
    let key = match profile_key.and_then(|k| k.secret_key().ok()) {
        Some(k) => k,
        None => {
            log_error!(logger, "No primary key to decrypt private zap");
            // We can't decrypt the message, treat it as an anonymous zap
            return (PrivacyLevel::Anonymous, Some(zap_req.content.clone()), None);
        }
    };
    // try to decrypt the message
    match decrypt_received_private_zap_message(key, zap_req) {
        Ok(event) => (
            PrivacyLevel::Private,
            Some(event.content.clone()),
            Some(event.pubkey),
        ),
        Err(e) => {
            // if we can't decrypt, treat it like it's an anonymous zap
            log_error!(logger, "Error decrypting private zap: {e}");
            (PrivacyLevel::Anonymous, Some(zap_req.content.clone()), None)
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use super::*;
    use crate::auth::MutinyAuthClient;
    use crate::federation::MockFedimintClient;
    use crate::generate_seed;
    use crate::storage::MemoryStorage;
    use crate::test_utils::{create_dummy_invoice, create_manager};
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::Network;
    use mockall::predicate::eq;
    use nostr::nips;
    use nostr::prelude::ZapRequestData;
    use nostr::util::hex;

    async fn create_hermes_client() -> HermesClient<MemoryStorage> {
        let storage = MemoryStorage::default();
        let logger = Arc::new(MutinyLogger::default());
        let mnemonic = generate_seed(12).unwrap();
        let xpriv = ExtendedPrivKey::new_master(Network::Regtest, &mnemonic.to_seed("")).unwrap();

        // Set up test auth client
        let auth_manager = create_manager();
        let lnurl_client = Arc::new(
            lnurl::Builder::default()
                .build_async()
                .expect("failed to make lnurl client"),
        );
        let auth_client = MutinyAuthClient::new(
            auth_manager,
            lnurl_client,
            logger.clone(),
            "https://auth-staging.mutinywallet.com".to_string(),
        );

        let blinded_auth = BlindAuthClient::new(
            xpriv,
            Arc::new(auth_client),
            Network::Regtest,
            "https://blind-auth-staging.mutinywallet.com".to_string(),
            &storage,
            logger.clone(),
        )
        .unwrap();

        HermesClient::new(
            xpriv,
            "https://signet.mutiny.plus".to_string(),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(blinded_auth),
            &storage,
            logger,
            Arc::new(AtomicBool::new(false)),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_correct_key_parity() {
        let secp = Secp256k1::new();

        // run 10 times to make sure we get the same parity each time
        for _ in 0..10 {
            let hermes = create_hermes_client().await;
            let (_, parity) = hermes.claim_key.x_only_public_key(&secp);
            assert_eq!(parity, Parity::Even);
        }
    }

    #[tokio::test]
    async fn test_check_username() {
        let hermes = create_hermes_client().await;
        let result = check_hermes_registration_info(
            &hermes.http_client,
            &hermes.base_url,
            hermes.client.clone(),
        )
        .await
        .unwrap();

        // new client should have no username
        assert!(result.name.is_none());
        assert!(result.disabled_zaps);
        assert!(result.federation_id.is_none());
    }

    #[tokio::test]
    async fn test_name_available() {
        let hermes = create_hermes_client().await;

        // "test1234" should be taken
        assert!(!hermes
            .check_available_name("test1234".to_string())
            .await
            .unwrap());

        // "x" is invalid, too short
        assert!(!hermes.check_available_name("x".to_string()).await.unwrap());

        // "thisisoverthe30characternamelimit" is invalid, too long
        assert!(!hermes
            .check_available_name("thisisoverthe30characternamelimit".to_string())
            .await
            .unwrap());

        // random string should be available
        // generate 32 hex and take first 20 characters
        let rand = Keys::generate().public_key().to_string();
        let string = rand.chars().take(20).collect::<String>();
        assert!(hermes.check_available_name(string).await.unwrap());
    }

    #[tokio::test]
    async fn test_claim_ecash_notification() {
        let logger = MutinyLogger::default();
        let storage = MemoryStorage::default();
        let claim_key = SecretKey::new(&mut OsRng);
        let mut fedimint_client = MockFedimintClient::new();

        let amount = 10_000;
        let (bolt11, preimage) = create_dummy_invoice(Some(amount), Network::Regtest, None);
        let notification = EcashNotification {
            amount,
            tweak_index: 0,
            federation_id: FederationId::dummy(),
            zap_request: None,
            bolt11: bolt11.clone(),
            preimage: hex::encode(preimage),
        };
        let timestamp = Timestamp::now();

        fedimint_client
            .expect_claim_external_receive()
            .once()
            .with(eq(claim_key), eq(vec![0]))
            .returning(|_, _| Ok(()));

        let info = claim_ecash_notification(
            notification,
            timestamp,
            &fedimint_client,
            &storage,
            &claim_key,
            None,
            &logger,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(info.preimage, Some(preimage));
        assert_eq!(info.status, HTLCStatus::Succeeded);
        assert_eq!(info.privacy_level, PrivacyLevel::NotAvailable);
        assert_eq!(info.bolt11, Some(bolt11.clone()));
        assert_eq!(info.fee_paid_msat, None);
        assert_eq!(info.amt_msat, MillisatAmount(Some(amount)));
        assert_eq!(info.last_update, timestamp.as_u64());

        // check that the payment was properly tagged
        let invoice_labels = storage.get_invoice_labels().unwrap();
        let labels = invoice_labels.get(&bolt11);
        assert!(labels.is_none()); // should not have been tagged
    }

    #[tokio::test]
    async fn test_claim_ecash_notification_with_zap() {
        let logger = MutinyLogger::default();
        let storage = MemoryStorage::default();
        let claim_key = SecretKey::new(&mut OsRng);
        let mut fedimint_client = MockFedimintClient::new();

        let amount = 10_000;
        let (bolt11, preimage) = create_dummy_invoice(Some(amount), Network::Regtest, None);
        let zap_req = EventBuilder::public_zap_request(ZapRequestData {
            public_key: Keys::generate().public_key(),
            relays: vec![],
            message: "".to_string(),
            amount: Some(amount),
            lnurl: None,
            event_id: None,
            event_coordinate: None,
        })
        .to_event(&Keys::generate())
        .unwrap();
        let notification = EcashNotification {
            amount,
            tweak_index: 0,
            federation_id: FederationId::dummy(),
            zap_request: Some(zap_req.as_json()),
            bolt11: bolt11.clone(),
            preimage: hex::encode(preimage),
        };
        let timestamp = Timestamp::now();

        fedimint_client
            .expect_claim_external_receive()
            .once()
            .with(eq(claim_key), eq(vec![0]))
            .returning(|_, _| Ok(()));

        let info = claim_ecash_notification(
            notification,
            timestamp,
            &fedimint_client,
            &storage,
            &claim_key,
            None,
            &logger,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(info.preimage, Some(preimage));
        assert_eq!(info.status, HTLCStatus::Succeeded);
        assert_eq!(info.privacy_level, PrivacyLevel::Public);
        assert_eq!(info.bolt11, Some(bolt11.clone()));
        assert_eq!(info.fee_paid_msat, None);
        assert_eq!(info.amt_msat, MillisatAmount(Some(amount)));
        assert_eq!(info.last_update, timestamp.as_u64());

        // check that the payment was properly tagged
        let invoice_labels = storage.get_invoice_labels().unwrap();
        let labels = invoice_labels.get(&bolt11).unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], zap_req.pubkey.to_bech32().unwrap());
    }

    #[tokio::test]
    async fn test_claim_ecash_notification_with_zap_message() {
        let logger = MutinyLogger::default();
        let storage = MemoryStorage::default();
        let claim_key = SecretKey::new(&mut OsRng);
        let mut fedimint_client = MockFedimintClient::new();

        let amount = 10_000;
        let (bolt11, preimage) = create_dummy_invoice(Some(amount), Network::Regtest, None);
        let message = "test message".to_string();
        let zap_req = EventBuilder::public_zap_request(ZapRequestData {
            public_key: Keys::generate().public_key(),
            relays: vec![],
            message: message.clone(),
            amount: Some(amount),
            lnurl: None,
            event_id: None,
            event_coordinate: None,
        })
        .to_event(&Keys::generate())
        .unwrap();
        let notification = EcashNotification {
            amount,
            tweak_index: 0,
            federation_id: FederationId::dummy(),
            zap_request: Some(zap_req.as_json()),
            bolt11: bolt11.clone(),
            preimage: hex::encode(preimage),
        };
        let timestamp = Timestamp::now();

        fedimint_client
            .expect_claim_external_receive()
            .once()
            .with(eq(claim_key), eq(vec![0]))
            .returning(|_, _| Ok(()));

        let info = claim_ecash_notification(
            notification,
            timestamp,
            &fedimint_client,
            &storage,
            &claim_key,
            None,
            &logger,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(info.preimage, Some(preimage));
        assert_eq!(info.status, HTLCStatus::Succeeded);
        assert_eq!(info.privacy_level, PrivacyLevel::Public);
        assert_eq!(info.bolt11, Some(bolt11.clone()));
        assert_eq!(info.fee_paid_msat, None);
        assert_eq!(info.amt_msat, MillisatAmount(Some(amount)));
        assert_eq!(info.last_update, timestamp.as_u64());

        // check that the payment was properly tagged
        let invoice_labels = storage.get_invoice_labels().unwrap();
        let labels = invoice_labels.get(&bolt11).unwrap();
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], zap_req.pubkey.to_bech32().unwrap());
        assert_eq!(labels[1], message);
    }

    #[tokio::test]
    async fn test_claim_ecash_notification_with_private_zap() {
        let logger = MutinyLogger::default();
        let storage = MemoryStorage::default();
        let claim_key = SecretKey::new(&mut OsRng);
        let profile_key = Keys::generate();
        let mut fedimint_client = MockFedimintClient::new();

        let amount = 10_000;
        let private_zap_keys = Keys::generate();
        let (bolt11, preimage) = create_dummy_invoice(Some(amount), Network::Regtest, None);
        let message = "test private message".to_string();
        let zap_req = nips::nip57::private_zap_request(
            ZapRequestData {
                public_key: profile_key.public_key(),
                relays: vec![],
                message: message.clone(),
                amount: Some(amount),
                lnurl: None,
                event_id: None,
                event_coordinate: None,
            },
            &private_zap_keys,
        )
        .unwrap();
        let notification = EcashNotification {
            amount,
            tweak_index: 0,
            federation_id: FederationId::dummy(),
            zap_request: Some(zap_req.as_json()),
            bolt11: bolt11.clone(),
            preimage: hex::encode(preimage),
        };
        let timestamp = Timestamp::now();

        fedimint_client
            .expect_claim_external_receive()
            .once()
            .with(eq(claim_key), eq(vec![0]))
            .returning(|_, _| Ok(()));

        let info = claim_ecash_notification(
            notification,
            timestamp,
            &fedimint_client,
            &storage,
            &claim_key,
            Some(&profile_key),
            &logger,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(info.preimage, Some(preimage));
        assert_eq!(info.status, HTLCStatus::Succeeded);
        assert_eq!(info.privacy_level, PrivacyLevel::Private);
        assert_eq!(info.bolt11, Some(bolt11.clone()));
        assert_eq!(info.fee_paid_msat, None);
        assert_eq!(info.amt_msat, MillisatAmount(Some(amount)));
        assert_eq!(info.last_update, timestamp.as_u64());

        // check that the payment was properly tagged
        let invoice_labels = storage.get_invoice_labels().unwrap();
        let labels = invoice_labels.get(&bolt11).unwrap();
        assert_eq!(labels.len(), 2);
        assert_eq!(
            labels[0],
            private_zap_keys.public_key().to_bech32().unwrap()
        );
        assert_eq!(labels[1], message);
    }

    #[tokio::test]
    async fn test_claim_ecash_notification_with_private_zap_no_profile() {
        let logger = MutinyLogger::default();
        let storage = MemoryStorage::default();
        let claim_key = SecretKey::new(&mut OsRng);
        let profile_key = Keys::generate();
        let mut fedimint_client = MockFedimintClient::new();

        let amount = 10_000;
        let private_zap_keys = Keys::generate();
        let (bolt11, preimage) = create_dummy_invoice(Some(amount), Network::Regtest, None);
        let message = "test private message".to_string();
        let zap_req = nips::nip57::private_zap_request(
            ZapRequestData {
                public_key: profile_key.public_key(),
                relays: vec![],
                message: message.clone(),
                amount: Some(amount),
                lnurl: None,
                event_id: None,
                event_coordinate: None,
            },
            &private_zap_keys,
        )
        .unwrap();
        let notification = EcashNotification {
            amount,
            tweak_index: 0,
            federation_id: FederationId::dummy(),
            zap_request: Some(zap_req.as_json()),
            bolt11: bolt11.clone(),
            preimage: hex::encode(preimage),
        };
        let timestamp = Timestamp::now();

        fedimint_client
            .expect_claim_external_receive()
            .once()
            .with(eq(claim_key), eq(vec![0]))
            .returning(|_, _| Ok(()));

        let info = claim_ecash_notification(
            notification,
            timestamp,
            &fedimint_client,
            &storage,
            &claim_key,
            None, // don't have a profile key
            &logger,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(info.preimage, Some(preimage));
        assert_eq!(info.status, HTLCStatus::Succeeded);
        assert_eq!(info.privacy_level, PrivacyLevel::Anonymous);
        assert_eq!(info.bolt11, Some(bolt11.clone()));
        assert_eq!(info.fee_paid_msat, None);
        assert_eq!(info.amt_msat, MillisatAmount(Some(amount)));
        assert_eq!(info.last_update, timestamp.as_u64());

        // check that the payment was properly tagged
        let invoice_labels = storage.get_invoice_labels().unwrap();
        let labels = invoice_labels.get(&bolt11);
        assert!(labels.is_none()); // should not have been tagged
    }

    #[tokio::test]
    async fn test_claim_ecash_notification_with_anonymous_zap() {
        let logger = MutinyLogger::default();
        let storage = MemoryStorage::default();
        let claim_key = SecretKey::new(&mut OsRng);
        let profile_key = Keys::generate();
        let mut fedimint_client = MockFedimintClient::new();

        let amount = 10_000;
        let (bolt11, preimage) = create_dummy_invoice(Some(amount), Network::Regtest, None);
        let message = "test anonymous message".to_string();
        let zap_req = nips::nip57::anonymous_zap_request(ZapRequestData {
            public_key: profile_key.public_key(),
            relays: vec![],
            message: message.clone(),
            amount: Some(amount),
            lnurl: None,
            event_id: None,
            event_coordinate: None,
        })
        .unwrap();
        let notification = EcashNotification {
            amount,
            tweak_index: 0,
            federation_id: FederationId::dummy(),
            zap_request: Some(zap_req.as_json()),
            bolt11: bolt11.clone(),
            preimage: hex::encode(preimage),
        };
        let timestamp = Timestamp::now();

        fedimint_client
            .expect_claim_external_receive()
            .once()
            .with(eq(claim_key), eq(vec![0]))
            .returning(|_, _| Ok(()));

        let info = claim_ecash_notification(
            notification,
            timestamp,
            &fedimint_client,
            &storage,
            &claim_key,
            Some(&profile_key),
            &logger,
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(info.preimage, Some(preimage));
        assert_eq!(info.status, HTLCStatus::Succeeded);
        assert_eq!(info.privacy_level, PrivacyLevel::Anonymous);
        assert_eq!(info.bolt11, Some(bolt11.clone()));
        assert_eq!(info.fee_paid_msat, None);
        assert_eq!(info.amt_msat, MillisatAmount(Some(amount)));
        assert_eq!(info.last_update, timestamp.as_u64());

        // check that the payment was properly tagged
        let invoice_labels = storage.get_invoice_labels().unwrap();
        let labels = invoice_labels.get(&bolt11).unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], message);
    }
}
