#![allow(clippy::too_many_arguments)]
use crate::actor::*;
use crate::event::*;
use crate::*;

use firestore::errors::FirestoreError;
use futures::future::FutureExt;
use futures::stream::{BoxStream, StreamExt};
use kitsune_p2p::actor::BroadcastData;
use kitsune_p2p::dependencies::kitsune_p2p_fetch;
use kitsune_p2p::event::*;
use kitsune_p2p::gossip::sharded_gossip::KitsuneDiagnostics;
use kitsune_p2p::KOp;
use kitsune_p2p::KitsuneOpData;
use kitsune_p2p_fetch::FetchContext;

use crate::types::AgentPubKeyExt;

use ghost_actor::dependencies::tracing;
use ghost_actor::dependencies::tracing_futures::Instrument;

use holochain_trace::tracing::warn;
use holochain_zome_types::zome::FunctionName;
use kitsune_p2p::actor::KitsuneP2pSender;
use kitsune_p2p::agent_store::AgentInfoSigned;
use std::collections::HashMap;
use std::collections::HashSet;
use std::future::Future;

macro_rules! timing_trace {
    ($code:block $($rest:tt)*) => {{
        let __start = std::time::Instant::now();
        let __out = $code;
        async move {
            let __out = __out.await;
            let __elapsed_s = __start.elapsed().as_secs_f64();
            if __elapsed_s >= 5.0 {
                tracing::warn!( elapsed_s = %__elapsed_s $($rest)* );
            } else {
                tracing::trace!( elapsed_s = %__elapsed_s $($rest)* );
            }
            __out
        }
    }};
}

#[derive(Clone)]
struct WrapEvtSender(futures::channel::mpsc::Sender<HolochainP2pEvent>);

impl WrapEvtSender {
    pub fn put_agent_info_signed(
        &self,
        dna_hash: DnaHash,
        peer_data: Vec<AgentInfoSigned>,
    ) -> impl Future<Output = HolochainP2pResult<()>> + 'static + Send {
        timing_trace!(
            { self.0.put_agent_info_signed(dna_hash, peer_data) },
            "(hp2p:handle) put_agent_info_signed",
        )
    }

    fn query_gossip_agents(
        &self,
        dna_hash: DnaHash,
        agents: Option<Vec<AgentPubKey>>,
        kitsune_space: Arc<kitsune_p2p::KitsuneSpace>,
        since_ms: u64,
        until_ms: u64,
        arc_set: Arc<kitsune_p2p_types::dht_arc::DhtArcSet>,
    ) -> impl Future<Output = HolochainP2pResult<Vec<AgentInfoSigned>>> + 'static + Send {
        timing_trace!(
            {
                self.0.query_gossip_agents(
                    dna_hash,
                    agents,
                    kitsune_space,
                    since_ms,
                    until_ms,
                    arc_set,
                )
            },
            "(hp2p:handle) query_gossip_agents",
        )
    }

    fn query_agent_info_signed(
        &self,
        dna_hash: DnaHash,
        agents: Option<HashSet<Arc<kitsune_p2p::KitsuneAgent>>>,
        kitsune_space: Arc<kitsune_p2p::KitsuneSpace>,
    ) -> impl Future<Output = HolochainP2pResult<Vec<AgentInfoSigned>>> + 'static + Send {
        timing_trace!(
            {
                self.0
                    .query_agent_info_signed(dna_hash, agents, kitsune_space)
            },
            "(hp2p:handle) query_agent_info_signed",
        )
    }

    fn query_agent_info_signed_near_basis(
        &self,
        dna_hash: DnaHash,
        kitsune_space: Arc<kitsune_p2p::KitsuneSpace>,
        basis_loc: u32,
        limit: u32,
    ) -> impl Future<Output = HolochainP2pResult<Vec<AgentInfoSigned>>> + 'static + Send {
        timing_trace!(
            {
                self.0
                    .query_agent_info_signed_near_basis(dna_hash, kitsune_space, basis_loc, limit)
            },
            "(hp2p:handle) query_agent_info_signed_near_basis",
        )
    }

    fn query_peer_density(
        &self,
        dna_hash: DnaHash,
        kitsune_space: Arc<kitsune_p2p::KitsuneSpace>,
        dht_arc: kitsune_p2p_types::dht_arc::DhtArc,
    ) -> impl Future<Output = HolochainP2pResult<kitsune_p2p_types::dht::PeerView>> + 'static + Send
    {
        timing_trace!(
            { self.0.query_peer_density(dna_hash, kitsune_space, dht_arc) },
            "(hp2p:handle) query_peer_density",
        )
    }

    fn call_remote(
        &self,
        dna_hash: DnaHash,
        from: AgentPubKey,
        signature: Signature,
        to_agent: AgentPubKey,
        zome_name: ZomeName,
        fn_name: FunctionName,
        cap_secret: Option<CapSecret>,
        payload: ExternIO,
        nonce: Nonce256Bits,
        expires_at: Timestamp,
    ) -> impl Future<Output = HolochainP2pResult<SerializedBytes>> + 'static + Send {
        timing_trace!(
            {
                self.0.call_remote(
                    dna_hash, from, signature, to_agent, zome_name, fn_name, cap_secret, payload,
                    nonce, expires_at,
                )
            },
            "(hp2p:handle) call_remote",
        )
    }

    fn publish(
        &self,
        dna_hash: DnaHash,
        request_validation_receipt: bool,
        countersigning_session: bool,
        ops: Vec<holochain_types::dht_op::DhtOp>,
    ) -> impl Future<Output = HolochainP2pResult<()>> + 'static + Send {
        let op_count = ops.len();
        timing_trace!({
            self.0.publish(dna_hash, request_validation_receipt, countersigning_session, ops)
        }, %op_count, "(hp2p:handle) publish")
    }

    fn get(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        dht_hash: holo_hash::AnyDhtHash,
        options: event::GetOptions,
    ) -> impl Future<Output = HolochainP2pResult<WireOps>> + 'static + Send {
        timing_trace!(
            { self.0.get(dna_hash, to_agent, dht_hash, options) },
            "(hp2p:handle) get",
        )
    }

    fn get_meta(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        dht_hash: holo_hash::AnyDhtHash,
        options: event::GetMetaOptions,
    ) -> impl Future<Output = HolochainP2pResult<MetadataSet>> + 'static + Send {
        timing_trace!(
            { self.0.get_meta(dna_hash, to_agent, dht_hash, options) },
            "(hp2p:handle) get_meta",
        )
    }

    fn get_links(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        link_key: WireLinkKey,
        options: event::GetLinksOptions,
    ) -> impl Future<Output = HolochainP2pResult<WireLinkOps>> + 'static + Send {
        timing_trace!(
            { self.0.get_links(dna_hash, to_agent, link_key, options) },
            "(hp2p:handle) get_links",
        )
    }

    fn count_links(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        query: WireLinkQuery,
    ) -> impl Future<Output = HolochainP2pResult<CountLinksResponse>> + 'static + Send {
        timing_trace!(
            { self.0.count_links(dna_hash, to_agent, query) },
            "(hp2p:handle) count_links"
        )
    }

    fn get_agent_activity(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        agent: AgentPubKey,
        query: ChainQueryFilter,
        options: event::GetActivityOptions,
    ) -> impl Future<Output = HolochainP2pResult<AgentActivityResponse<ActionHash>>> + 'static + Send
    {
        timing_trace!(
            {
                self.0
                    .get_agent_activity(dna_hash, to_agent, agent, query, options)
            },
            "(hp2p:handle) get_agent_activity",
        )
    }

    fn must_get_agent_activity(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        agent: AgentPubKey,
        filter: holochain_zome_types::chain::ChainFilter,
    ) -> impl Future<Output = HolochainP2pResult<MustGetAgentActivityResponse>> + 'static + Send
    {
        timing_trace!(
            {
                self.0
                    .must_get_agent_activity(dna_hash, to_agent, agent, filter)
            },
            "(hp2p:handle) must_get_agent_activity",
        )
    }

    fn validation_receipts_received(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        receipts: ValidationReceiptBundle,
    ) -> impl Future<Output = HolochainP2pResult<()>> + 'static + Send {
        timing_trace!(
            {
                self.0
                    .validation_receipts_received(dna_hash, to_agent, receipts)
            },
            "(hp2p:handle) validation_receipt_received",
        )
    }

    fn query_op_hashes(
        &self,
        dna_hash: DnaHash,
        arc_set: kitsune_p2p::dht_arc::DhtArcSet,
        window: TimeWindow,
        max_ops: usize,
        include_limbo: bool,
    ) -> impl Future<
        Output = HolochainP2pResult<Option<(Vec<holo_hash::DhtOpHash>, TimeWindowInclusive)>>,
    >
           + 'static
           + Send {
        timing_trace!(
            {
                self.0
                    .query_op_hashes(dna_hash, arc_set, window, max_ops, include_limbo)
            },
            "(hp2p:handle) query_op_hashes",
        )
    }

    fn fetch_op_data(
        &self,
        dna_hash: DnaHash,
        query: FetchOpDataQuery,
    ) -> impl Future<
        Output = HolochainP2pResult<Vec<(holo_hash::DhtOpHash, holochain_types::dht_op::DhtOp)>>,
    >
           + 'static
           + Send {
        timing_trace!(
            { self.0.fetch_op_data(dna_hash, query) },
            "(hp2p:handle) fetch_op_data",
        )
    }

    fn sign_network_data(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        data: Vec<u8>,
    ) -> impl Future<Output = HolochainP2pResult<Signature>> + 'static + Send {
        let byte_count = data.len();
        timing_trace!(
            { self.0.sign_network_data(dna_hash, to_agent, data) },
            %byte_count,
            "(hp2p:handle) sign_network_data",
        )
    }

    fn countersigning_session_negotiation(
        &self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        message: event::CountersigningSessionNegotiationMessage,
    ) -> impl Future<Output = HolochainP2pResult<()>> + 'static + Send {
        timing_trace!(
            {
                self.0
                    .countersigning_session_negotiation(dna_hash, to_agent, message)
            },
            "(hp2p:handle) countersigning_session_negotiation"
        )
    }
}

pub(crate) struct HolochainP2pActor {
    // db: FirestoreDb,
    // cache: firestore::FirestoreCache<
    //     FirestorePersistentCacheBackend,
    //     FirestoreTempFilesListenStateStorage,
    // >,
    // config: kitsune_p2p_types::config::KitsuneP2pConfig,
    // evt_sender: WrapEvtSender,
    // kitsune_p2p: ghost_actor::GhostSender<kitsune_p2p::actor::KitsuneP2p>,
    // host: kitsune_p2p::HostApi,
}

impl ghost_actor::GhostControlHandler for HolochainP2pActor {
    fn handle_ghost_actor_shutdown(
        self,
    ) -> ghost_actor::dependencies::must_future::MustBoxFuture<'static, ()> {
        // unimplemented!()
        use ghost_actor::GhostControlSender;
        async move {
            // let _ = self.kitsune_p2p.ghost_actor_shutdown_immediate().await;
        }
        .boxed()
        .into()
    }
}

use firestore::*;
use gcloud_sdk::TokenSourceType;

fn service_account_key() -> String {
    std::env!("SERVICE_ACCOUNT_KEY").into()
}

const PROJECT_ID: &'static str = "rostanga-ce319";

static DB: tokio::sync::RwLock<Option<FirestoreDb>> = tokio::sync::RwLock::const_new(None);

async fn db() -> Result<FirestoreDb, HolochainP2pError> {
    let lock = DB.read().await;

    if let Some(info) = lock.to_owned() {
        return Ok(info.clone());
    }
    std::mem::drop(lock);
    let mut lock = DB.write().await;
    let db = FirestoreDb::with_options_token_source(
        FirestoreDbOptions {
            google_project_id: PROJECT_ID.into(),
            database_id: String::from("(default)"),
            max_retries: 10,
            firebase_api_url: None,
        },
        gcloud_sdk::GCP_DEFAULT_SCOPES.clone(),
        TokenSourceType::Json(service_account_key()),
    )
    .await?;

    *lock = Some(db.clone());

    Ok(db)
}

static CACHED_DBS: tokio::sync::RwLock<Option<HashMap<DnaHash, FirestoreDb>>> =
    tokio::sync::RwLock::const_new(None);

async fn cached_db(dna_hash: DnaHash) -> Result<FirestoreDb, HolochainP2pError> {
    let lock = CACHED_DBS.read().await;

    // let mut map: HashMap<DnaHash, FirestoreDb> = lock.unwrap_or_default();

    if let Some(map) = lock.as_ref() {
        if let Some(cache) = map.get(&dna_hash) {
            return Ok(cache.clone());
        }
    }
    std::mem::drop(lock);
    let mut lock = CACHED_DBS.write().await;

    if let None = lock.as_ref() {
        *lock = Some(HashMap::new());
    }
    let d = db().await?;

    let mut cache = FirestoreCache::new(
        format!("dna_{dna_hash}").into(),
        &d,
        FirestorePersistentCacheBackend::new(
            FirestoreCacheConfiguration::new()
                .add_collection_config(
                    &d,
                    FirestoreCacheCollectionConfiguration::new(
                        "entries",
                        FirestoreListenerTarget::new(1000),
                        FirestoreCacheCollectionLoadMode::PreloadAllIfEmpty,
                    )
                    .with_parent(format!(
                        "projects/{PROJECT_ID}/databases/(default)/documents/dnas/{dna_hash}"
                    )),
                )
                .add_collection_config(
                    &d,
                    FirestoreCacheCollectionConfiguration::new(
                        "actions",
                        FirestoreListenerTarget::new(1000),
                        FirestoreCacheCollectionLoadMode::PreloadAllIfEmpty,
                    )
                    .with_parent(format!(
                        "projects/{PROJECT_ID}/databases/(default)/documents/dnas/{dna_hash}"
                    )),
                ),
        )?,
        FirestoreTempFilesListenStateStorage::new(),
    )
    .await?;

    cache.load().await?;

    let db = d.read_through_cache(&cache);

    // let map = &mut lock;
    lock.as_mut().unwrap().insert(dna_hash, db.clone());
    // *lock = Some(map);

    Ok(db)
}

/// Init DNA
pub async fn init_dna_if_necessary(dna_hash: DnaHash) -> Result<(), HolochainP2pError> {
    let db = db().await?;

    match db
        .fluent()
        .insert()
        .into("dnas")
        .document_id(DnaHashB64::from(dna_hash.clone()).to_string())
        .object(&DnaRecord { dna_hash })
        .execute::<DnaRecord>()
        .await
    {
        Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
        Err(err) => Err(HolochainP2pError::Firestore(err)),
    }?;
    tracing::log::info!("Initialized DNA");
    Ok(())
}

impl HolochainP2pActor {
    /// constructor
    pub async fn new(
        config: kitsune_p2p_types::config::KitsuneP2pConfig,
        tls_config: kitsune_p2p_types::tls::TlsConfig,
        channel_factory: ghost_actor::actor_builder::GhostActorChannelFactory<Self>,
        evt_sender: futures::channel::mpsc::Sender<HolochainP2pEvent>,
        host: kitsune_p2p::HostApi,
    ) -> HolochainP2pResult<Self> {
        // let (kitsune_p2p, kitsune_p2p_events) =
        //     kitsune_p2p::spawn_kitsune_p2p(config.clone(), tls_config, host.clone()).await?;

        // channel_factory.attach_receiver(kitsune_p2p_events).await?;
        Ok(Self {
                   // evt_sender: WrapEvtSender(evt_sender),
                   // kitsune_p2p,
                   // host,
        })
    }

    /// receiving an incoming request from a remote node
    #[allow(clippy::too_many_arguments)]
    fn handle_incoming_call_remote(
        &mut self,
        dna_hash: DnaHash,
        from: AgentPubKey,
        signature: Signature,
        to_agent: AgentPubKey,
        zome_name: ZomeName,
        fn_name: FunctionName,
        cap_secret: Option<CapSecret>,
        data: Vec<u8>,
        nonce: Nonce256Bits,
        expires_at: Timestamp,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<Vec<u8>> {
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     let res = evt_sender
        //         .call_remote(
        //             dna_hash,
        //             from,
        //             signature,
        //             to_agent,
        //             zome_name,
        //             fn_name,
        //             cap_secret,
        //             ExternIO::from(data),
        //             nonce,
        //             expires_at,
        //         )
        //         .await;
        //     res.map_err(kitsune_p2p::KitsuneP2pError::from)
        //         .map(|res| UnsafeBytes::from(res).into())
        // }
        // .boxed()
        // .into())
        unimplemented!()
    }

    /// receiving an incoming get request from a remote node
    #[tracing::instrument(skip(self, dna_hash, to_agent, dht_hash, options), level = "trace")]
    fn handle_incoming_get(
        &mut self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        dht_hash: holo_hash::AnyDhtHash,
        options: event::GetOptions,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<Vec<u8>> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     let res = evt_sender.get(dna_hash, to_agent, dht_hash, options).await;
        //     res.and_then(|r| Ok(SerializedBytes::try_from(r)?))
        //         .map_err(kitsune_p2p::KitsuneP2pError::from)
        //         .map(|res| UnsafeBytes::from(res).into())
        // }
        // .instrument(tracing::debug_span!("incoming_get_task"))
        // .boxed()
        // .into())
    }

    /// receiving an incoming get_meta request from a remote node
    fn handle_incoming_get_meta(
        &mut self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        dht_hash: holo_hash::AnyDhtHash,
        options: event::GetMetaOptions,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<Vec<u8>> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     let res = evt_sender
        //         .get_meta(dna_hash, to_agent, dht_hash, options)
        //         .await;
        //     res.and_then(|r| Ok(SerializedBytes::try_from(r)?))
        //         .map_err(kitsune_p2p::KitsuneP2pError::from)
        //         .map(|res| UnsafeBytes::from(res).into())
        // }
        // .boxed()
        // .into())
    }

    /// receiving an incoming get_links request from a remote node
    fn handle_incoming_get_links(
        &mut self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        link_key: WireLinkKey,
        options: event::GetLinksOptions,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<Vec<u8>> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     let res = evt_sender
        //         .get_links(dna_hash, to_agent, link_key, options)
        //         .await;
        //     res.and_then(|r| Ok(SerializedBytes::try_from(r)?))
        //         .map_err(kitsune_p2p::KitsuneP2pError::from)
        //         .map(|res| UnsafeBytes::from(res).into())
        // }
        // .boxed()
        // .into())
    }

    fn handle_incoming_count_links(
        &mut self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        query: WireLinkQuery,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<Vec<u8>> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     let res = evt_sender.count_links(dna_hash, to_agent, query).await;
        //     res.and_then(|r| Ok(SerializedBytes::try_from(r)?))
        //         .map_err(kitsune_p2p::KitsuneP2pError::from)
        //         .map(|res| UnsafeBytes::from(res).into())
        // }
        // .boxed()
        // .into())
    }

    /// receiving an incoming get_links request from a remote node
    fn handle_incoming_get_agent_activity(
        &mut self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        agent: AgentPubKey,
        query: ChainQueryFilter,
        options: event::GetActivityOptions,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<Vec<u8>> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     let res = evt_sender
        //         .get_agent_activity(dna_hash, to_agent, agent, query, options)
        //         .await;
        //     res.and_then(|r| Ok(SerializedBytes::try_from(r)?))
        //         .map_err(kitsune_p2p::KitsuneP2pError::from)
        //         .map(|res| UnsafeBytes::from(res).into())
        // }
        // .boxed()
        // .into())
    }

    /// receiving an incoming must_get_agent_activity request from a remote node
    fn handle_incoming_must_get_agent_activity(
        &mut self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        agent: AgentPubKey,
        filter: holochain_zome_types::chain::ChainFilter,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<Vec<u8>> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     let res = evt_sender
        //         .must_get_agent_activity(dna_hash, to_agent, agent, filter)
        //         .await;
        //     res.and_then(|r| Ok(SerializedBytes::try_from(r)?))
        //         .map_err(kitsune_p2p::KitsuneP2pError::from)
        //         .map(|res| UnsafeBytes::from(res).into())
        // }
        // .boxed()
        // .into())
    }

    /// receiving an incoming publish from a remote node
    fn handle_incoming_publish(
        &mut self,
        dna_hash: DnaHash,
        request_validation_receipt: bool,
        countersigning_session: bool,
        ops: Vec<holochain_types::dht_op::DhtOp>,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<()> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     evt_sender
        //         .publish(
        //             dna_hash,
        //             request_validation_receipt,
        //             countersigning_session,
        //             ops,
        //         )
        //         .await?;
        //     Ok(())
        // }
        // .boxed()
        // .into())
    }

    /// receiving an incoming validation receipt from a remote node
    fn handle_incoming_validation_receipt(
        &mut self,
        dna_hash: DnaHash,
        agent_pub_key: AgentPubKey,
        receipts: ValidationReceiptBundle,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<()> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     evt_sender
        //         .validation_receipts_received(dna_hash, agent_pub_key, receipts)
        //         .await?;

        //     // validation receipts don't need a response
        //     Ok(())
        // }
        // .boxed()
        // .into())
    }

    fn handle_incoming_countersigning_session_negotiation(
        &mut self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        message: CountersigningSessionNegotiationMessage,
    ) -> kitsune_p2p::actor::KitsuneP2pHandlerResult<()> {
        unimplemented!()
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     evt_sender
        //         .countersigning_session_negotiation(dna_hash, to_agent, message)
        //         .await?;
        //     Ok(())
        // }
        // .boxed()
        // .into())
    }
}

impl ghost_actor::GhostHandler<kitsune_p2p::event::KitsuneP2pEvent> for HolochainP2pActor {}

impl kitsune_p2p::event::KitsuneP2pEventHandler for HolochainP2pActor {
    /// We need to store signed agent info.
    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_put_agent_info_signed(
        &mut self,
        input: kitsune_p2p::event::PutAgentInfoSignedEvt,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<()> {
        unimplemented!()
        // let kitsune_p2p::event::PutAgentInfoSignedEvt { space, peer_data } = input;
        // let space = DnaHash::from_kitsune(&space);
        // let evt_sender = self.evt_sender.clone();
        // Ok(
        //     async move { Ok(evt_sender.put_agent_info_signed(space, peer_data).await?) }
        //         .boxed()
        //         .into(),
        // )
    }

    /// We need to get previously stored agent info. A single kitusne agent query
    /// can take one of three Holochain agent query paths. We do "duck typing"
    /// on the query object to determine which query path to take. The reason for
    /// this is that Holochain is optimized for these three query types, while
    /// kitsune has a more general interface.
    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_query_agents(
        &mut self,
        input: kitsune_p2p::event::QueryAgentsEvt,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<Vec<AgentInfoSigned>> {
        unimplemented!()
        // let kitsune_p2p::event::QueryAgentsEvt {
        //     space,
        //     agents,
        //     window,
        //     arc_set,
        //     near_basis,
        //     limit,
        // } = input;

        // let h_space = DnaHash::from_kitsune(&space);
        // let evt_sender = self.evt_sender.clone();

        // Ok(async move {
        //     let agents = match (agents, window, arc_set, near_basis, limit) {
        //         // If only basis and limit are set, this is a "near basis" query
        //         (None, None, None, Some(basis), Some(limit)) => {
        //             evt_sender
        //                 .query_agent_info_signed_near_basis(h_space, space, basis.as_u32(), limit)
        //                 .await?
        //         }

        //         // If arc_set is set, this is a "gossip agents" query
        //         (agents, window, Some(arc_set), None, None) => {
        //             let window = window.unwrap_or_else(full_time_window);
        //             let h_agents =
        //                 agents.map(|agents| agents.iter().map(AgentPubKey::from_kitsune).collect());
        //             let since_ms = window.start.as_millis().max(0) as u64;
        //             let until_ms = window.end.as_millis().max(0) as u64;
        //             evt_sender
        //                 .query_gossip_agents(h_space, h_agents, space, since_ms, until_ms, arc_set)
        //                 .await?
        //         }

        //         // Otherwise, do a simple agent query with optional agent filter
        //         (agents, None, None, None, None) => {
        //             evt_sender
        //                 .query_agent_info_signed(h_space, agents, space)
        //                 .await?
        //         }

        //         // If none of the above match, we have no implementation for such a query
        //         // and must fail
        //         tuple => unimplemented!(
        //             "Holochain cannot interpret the QueryAgentsEvt data as given: {:?}",
        //             tuple
        //         ),
        //     };
        //     Ok(agents)
        // }
        // .boxed()
        // .into())
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_query_peer_density(
        &mut self,
        space: Arc<kitsune_p2p::KitsuneSpace>,
        dht_arc: kitsune_p2p_types::dht_arc::DhtArc,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<kitsune_p2p_types::dht::PeerView> {
        unimplemented!()
        // let h_space = DnaHash::from_kitsune(&space);
        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     Ok(evt_sender
        //         .query_peer_density(h_space, space, dht_arc)
        //         .await?)
        // }
        // .boxed()
        // .into())
    }

    /// Handle an incoming call.
    #[tracing::instrument(skip(self, space, to_agent, payload), level = "trace")]
    fn handle_call(
        &mut self,
        space: Arc<kitsune_p2p::KitsuneSpace>,
        to_agent: Arc<kitsune_p2p::KitsuneAgent>,
        payload: Vec<u8>,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<Vec<u8>> {
        unimplemented!()
        // let space = DnaHash::from_kitsune(&space);
        // let to_agent = AgentPubKey::from_kitsune(&to_agent);

        // let request =
        //     crate::wire::WireMessage::decode(payload.as_ref()).map_err(HolochainP2pError::from)?;

        // match request {
        //     crate::wire::WireMessage::CallRemote {
        //         zome_name,
        //         fn_name,
        //         cap_secret,
        //         data,
        //         from_agent,
        //         signature,
        //         to_agent,
        //         nonce,
        //         expires_at,
        //     } => self.handle_incoming_call_remote(
        //         space, from_agent, signature, to_agent, zome_name, fn_name, cap_secret, data,
        //         *nonce, expires_at,
        //     ),
        //     crate::wire::WireMessage::CallRemoteMulti {
        //         zome_name,
        //         fn_name,
        //         cap_secret,
        //         data,
        //         from_agent,
        //         to_agents,
        //         nonce,
        //         expires_at,
        //     } => {
        //         match to_agents
        //             .into_iter()
        //             .find(|(_signature, agent)| agent == &to_agent)
        //         {
        //             Some((signature, to_agent)) => self.handle_incoming_call_remote(
        //                 space, from_agent, signature, to_agent, zome_name, fn_name, cap_secret,
        //                 data, *nonce, expires_at,
        //             ),
        //             None => Err(HolochainP2pError::RoutingAgentError(to_agent).into()),
        //         }
        //     }
        //     crate::wire::WireMessage::Get { dht_hash, options } => {
        //         self.handle_incoming_get(space, to_agent, dht_hash, options)
        //     }
        //     crate::wire::WireMessage::GetMeta { dht_hash, options } => {
        //         self.handle_incoming_get_meta(space, to_agent, dht_hash, options)
        //     }
        //     crate::wire::WireMessage::GetLinks { link_key, options } => {
        //         self.handle_incoming_get_links(space, to_agent, link_key, options)
        //     }
        //     WireMessage::CountLinks { query } => {
        //         self.handle_incoming_count_links(space, to_agent, query)
        //     }
        //     crate::wire::WireMessage::GetAgentActivity {
        //         agent,
        //         query,
        //         options,
        //     } => self.handle_incoming_get_agent_activity(space, to_agent, agent, query, options),
        //     crate::wire::WireMessage::MustGetAgentActivity { agent, filter } => {
        //         self.handle_incoming_must_get_agent_activity(space, to_agent, agent, filter)
        //     }
        //     crate::wire::WireMessage::ValidationReceipts { .. } => {
        //         Err(HolochainP2pError::invalid_p2p_message(
        //             "invalid: validation receipts are now notifications rather than requests, please upgrade".to_string(),
        //         )
        //             .into())
        //     }
        //     // holochain_p2p only broadcasts this message.
        //     crate::wire::WireMessage::CountersigningSessionNegotiation { .. }
        //     | crate::wire::WireMessage::PublishCountersign { .. } => {
        //         Err(HolochainP2pError::invalid_p2p_message(
        //             "invalid: countersigning messages are broadcast, not requests".to_string(),
        //         )
        //         .into())
        //     }
        // }
    }

    /// Handle an incoming notify.
    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_notify(
        &mut self,
        space: Arc<kitsune_p2p::KitsuneSpace>,
        to_agent: Arc<kitsune_p2p::KitsuneAgent>,
        payload: Vec<u8>,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<()> {
        unimplemented!()
        // let space = DnaHash::from_kitsune(&space);
        // let to_agent = AgentPubKey::from_kitsune(&to_agent);

        // let request =
        //     crate::wire::WireMessage::decode(payload.as_ref()).map_err(HolochainP2pError::from)?;

        // match request {
        //     // error on these call type messages
        //     crate::wire::WireMessage::Get { .. }
        //     | crate::wire::WireMessage::GetMeta { .. }
        //     | crate::wire::WireMessage::GetLinks { .. }
        //     | crate::wire::WireMessage::CountLinks { .. }
        //     | crate::wire::WireMessage::GetAgentActivity { .. }
        //     | crate::wire::WireMessage::MustGetAgentActivity { .. } => {
        //         Err(HolochainP2pError::invalid_p2p_message(
        //             "invalid call type message in a notify".to_string(),
        //         )
        //         .into())
        //     }
        //     crate::wire::WireMessage::CallRemote {
        //         zome_name,
        //         fn_name,
        //         from_agent,
        //         signature,
        //         to_agent,
        //         cap_secret,
        //         data,
        //         nonce,
        //         expires_at,
        //     } => {
        //         let fut = self.handle_incoming_call_remote(
        //             space, from_agent, signature, to_agent, zome_name, fn_name, cap_secret, data,
        //             *nonce, expires_at,
        //         );
        //         Ok(async move {
        //             let _ = fut?.await?;
        //             Ok(())
        //         }
        //         .boxed()
        //         .into())
        //     }
        //     crate::wire::WireMessage::CallRemoteMulti {
        //         zome_name,
        //         fn_name,
        //         from_agent,
        //         to_agents,
        //         cap_secret,
        //         data,
        //         nonce,
        //         expires_at,
        //     } => {
        //         match to_agents
        //             .into_iter()
        //             .find(|(_signature, agent)| agent == &to_agent)
        //         {
        //             Some((signature, to_agent)) => {
        //                 let fut = self.handle_incoming_call_remote(
        //                     space, from_agent, signature, to_agent, zome_name, fn_name, cap_secret,
        //                     data, *nonce, expires_at,
        //                 );
        //                 Ok(async move {
        //                     let _ = fut?.await?;
        //                     Ok(())
        //                 }
        //                 .boxed()
        //                 .into())
        //             }
        //             None => Err(HolochainP2pError::RoutingAgentError(to_agent).into()),
        //         }
        //     }
        //     WireMessage::ValidationReceipts { receipts } => {
        //         self.handle_incoming_validation_receipt(space, to_agent, receipts)
        //     }
        //     crate::wire::WireMessage::CountersigningSessionNegotiation { message } => {
        //         self.handle_incoming_countersigning_session_negotiation(space, to_agent, message)
        //     }
        //     crate::wire::WireMessage::PublishCountersign { flag, op } => {
        //         self.handle_incoming_publish(space, false, flag, vec![op])
        //     }
        // }
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_receive_ops(
        &mut self,
        space: Arc<kitsune_p2p::KitsuneSpace>,
        ops: Vec<KOp>,
        context: Option<FetchContext>,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<()> {
        unimplemented!()
        // let space = DnaHash::from_kitsune(&space);
        // let by = self
        //     .config
        //     .tracing_scope
        //     .clone()
        //     .unwrap_or_else(|| "<NONE>".to_string());

        // let ops = ops
        //     .into_iter()
        //     .map(|op_data| {
        //         let op = crate::wire::WireDhtOpData::decode(op_data.0.clone())
        //             .map_err(HolochainP2pError::from)?
        //             .op_data;

        //         aitia::trace!(&hc_sleuth::Event::Fetched {
        //             by: by.clone(),
        //             op: op.to_hash()
        //         });

        //         Ok(op)
        //     })
        //     .collect::<Result<_, HolochainP2pError>>()?;
        // if let Some(context) = context {
        //     self.handle_incoming_publish(
        //         space,
        //         context.has_request_validation_receipt(),
        //         context.has_countersigning_session(),
        //         ops,
        //     )
        // } else {
        //     self.handle_incoming_publish(space, false, false, ops)
        // }
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_query_op_hashes(
        &mut self,
        input: kitsune_p2p::event::QueryOpHashesEvt,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<
        Option<(Vec<Arc<kitsune_p2p::KitsuneOpHash>>, TimeWindowInclusive)>,
    > {
        unimplemented!()
        // let kitsune_p2p::event::QueryOpHashesEvt {
        //     space,
        //     arc_set,
        //     window,
        //     max_ops,
        //     include_limbo,
        // } = input;
        // let space = DnaHash::from_kitsune(&space);

        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     Ok(evt_sender
        //         .query_op_hashes(space, arc_set, window, max_ops, include_limbo)
        //         .await?
        //         .map(|(h, time)| (h.into_iter().map(|h| h.into_kitsune()).collect(), time)))
        // }
        // .boxed()
        // .into())
    }

    #[allow(clippy::needless_collect)]
    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_fetch_op_data(
        &mut self,
        input: kitsune_p2p::event::FetchOpDataEvt,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<Vec<(Arc<kitsune_p2p::KitsuneOpHash>, KOp)>>
    {
        unimplemented!()
        // let kitsune_p2p::event::FetchOpDataEvt { space, query } = input;
        // let space = DnaHash::from_kitsune(&space);
        // let query = FetchOpDataQuery::from_kitsune(query);

        // let evt_sender = self.evt_sender.clone();
        // Ok(async move {
        //     let mut out = vec![];
        //     for (op_hash, dht_op) in evt_sender.fetch_op_data(space.clone(), query).await? {
        //         out.push((
        //             op_hash.into_kitsune(),
        //             KitsuneOpData::new(
        //                 crate::wire::WireDhtOpData { op_data: dht_op }
        //                     .encode()
        //                     .map_err(kitsune_p2p::KitsuneP2pError::other)?,
        //             ),
        //         ));
        //     }
        //     Ok(out)
        // }
        // .boxed()
        // .into())
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_sign_network_data(
        &mut self,
        input: kitsune_p2p::event::SignNetworkDataEvt,
    ) -> kitsune_p2p::event::KitsuneP2pEventHandlerResult<kitsune_p2p::KitsuneSignature> {
        unimplemented!()
        //     let space = DnaHash::from_kitsune(&input.space);
        //     let agent = AgentPubKey::from_kitsune(&input.agent);
        //     let fut = self
        //         .evt_sender
        //         .sign_network_data(space, agent, input.data.to_vec());
        //     Ok(async move {
        //         let sig = fut.await?.0;
        //         Ok(sig.to_vec().into())
        //     }
        //     .boxed()
        //     .into())
    }
}

impl ghost_actor::GhostHandler<HolochainP2p> for HolochainP2pActor {}

#[derive(Serialize, Deserialize, Debug)]
struct DnaRecord {
    dna_hash: DnaHash,
}

#[derive(Serialize, Deserialize, Debug)]
struct LinkBaseRecord {
    base: AnyLinkableHash,
}

impl HolochainP2pHandler for HolochainP2pActor {
    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_join(
        &mut self,
        dna_hash: DnaHash,
        agent_pub_key: AgentPubKey,
        maybe_agent_info: Option<AgentInfoSigned>,
        initial_arc: Option<crate::dht_arc::DhtArc>,
    ) -> HolochainP2pHandlerResult<()> {
        Ok(async move { Ok(()) }.boxed().into())
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_leave(
        &mut self,
        dna_hash: DnaHash,
        agent_pub_key: AgentPubKey,
    ) -> HolochainP2pHandlerResult<()> {
        Ok(async move { Ok(()) }.boxed().into())
    }

    /// Dispatch an outgoing remote call.
    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_call_remote(
        &mut self,
        dna_hash: DnaHash,
        from_agent: AgentPubKey,
        signature: Signature,
        to_agent: AgentPubKey,
        zome_name: ZomeName,
        fn_name: FunctionName,
        cap_secret: Option<CapSecret>,
        payload: ExternIO,
        nonce: Nonce256Bits,
        expires_at: Timestamp,
    ) -> HolochainP2pHandlerResult<SerializedBytes> {
        // let space = dna_hash.into_kitsune();
        // let to_agent_kitsune = to_agent.clone().into_kitsune();

        // let req = crate::wire::WireMessage::call_remote(
        //     zome_name, fn_name, from_agent, signature, to_agent, cap_secret, payload, nonce,
        //     expires_at,
        // )
        // .encode()?;

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(async move {
        //     let result: Vec<u8> = kitsune_p2p
        //         .rpc_single(space, to_agent_kitsune, req, None)
        //         .await?;
        //     Ok(UnsafeBytes::from(result).into())
        // }
        // .boxed()
        // .into())
        unimplemented!()
    }

    /// Dispatch an outgoing signal.
    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_send_remote_signal(
        &mut self,
        dna_hash: DnaHash,
        from_agent: AgentPubKey,
        to_agent_list: Vec<(Signature, AgentPubKey)>,
        zome_name: ZomeName,
        fn_name: FunctionName,
        cap: Option<CapSecret>,
        payload: ExternIO,
        nonce: Nonce256Bits,
        expires_at: Timestamp,
    ) -> HolochainP2pHandlerResult<()> {
        unimplemented!()
        // let space = dna_hash.into_kitsune();
        // let to_agents = to_agent_list
        //     .iter()
        //     .map(|(_signature, agent)| agent.clone().into_kitsune())
        //     .collect();

        // let req = crate::wire::WireMessage::call_remote_multi(
        //     zome_name,
        //     fn_name,
        //     from_agent,
        //     to_agent_list,
        //     cap,
        //     payload,
        //     nonce,
        //     expires_at,
        // )
        // .encode()?;

        // let timeout = self.config.tuning_params.implicit_timeout();

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(async move {
        //     kitsune_p2p
        //         .targeted_broadcast(space, to_agents, timeout, req, true)
        //         .await?;
        //     Ok(())
        // }
        // .boxed()
        // .into())
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_publish(
        &mut self,
        dna_hash: DnaHash,
        request_validation_receipt: bool,
        countersigning_session: bool,
        basis_hash: holo_hash::OpBasis,
        source: AgentPubKey,
        op_hash_list: Vec<OpHashSized>,
        timeout_ms: Option<u64>,
        reflect_ops: Option<Vec<DhtOp>>,
    ) -> HolochainP2pHandlerResult<()> {
        Ok(async move {
            let db = db().await?;
            if let Some(ops) = reflect_ops {
                let parent_path = db.parent_path("dnas", DnaHashB64::from(dna_hash).to_string())?;
                for op in ops {
                    match op {
                        DhtOp::RegisterUpdatedRecord(signature, update, entry) => {
                            let action = SignedHashed {
                                hashed: HoloHashed::from_content_sync(Action::Update(
                                    update.clone(),
                                )),
                                signature,
                            };
                            let p = parent_path.clone().at(
                                "actions",
                                ActionHashB64::from(update.original_action_address.clone())
                                    .to_string(),
                            )?;

                            match db
                                .fluent()
                                .insert()
                                .into("updates")
                                .document_id(
                                    ActionHashB64::from(action.action_address().clone())
                                        .to_string(),
                                )
                                .parent(&p)
                                .object(&action)
                                .execute::<SignedHashed<Action>>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not create record");
                        }
                        DhtOp::RegisterUpdatedContent(signature, update, entry) => {
                            let action = SignedHashed {
                                hashed: HoloHashed::from_content_sync(Action::Update(
                                    update.clone(),
                                )),
                                signature,
                            };
                            let p = parent_path.clone().at(
                                "entries",
                                EntryHashB64::from(update.original_entry_address.clone())
                                    .to_string(),
                            )?;
                            // .expect("Can't build parent path");

                            match db
                                .fluent()
                                .insert()
                                .into("updates")
                                .document_id(
                                    ActionHashB64::from(action.action_address().clone())
                                        .to_string(),
                                )
                                .parent(&p)
                                .object(&action)
                                .execute::<SignedActionHashed>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not create record");
                        }
                        DhtOp::RegisterDeletedBy(signature, delete) => {
                            let action = SignedHashed {
                                hashed: HoloHashed::from_content_sync(Action::Delete(
                                    delete.clone(),
                                )),
                                signature,
                            };
                            let p = parent_path.clone().at(
                                "actions",
                                ActionHashB64::from(delete.deletes_address.clone()).to_string(),
                            )?;
                            // .expect("Can't build parent path");

                            match db
                                .fluent()
                                .insert()
                                .into("deletes")
                                .document_id(
                                    ActionHashB64::from(action.action_address().clone())
                                        .to_string(),
                                )
                                .parent(&p)
                                .object(&action)
                                .execute::<SignedActionHashed>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not create record");
                        }
                        DhtOp::RegisterDeletedEntryAction(signature, delete) => {
                            let action = SignedHashed {
                                hashed: HoloHashed::from_content_sync(Action::Delete(
                                    delete.clone(),
                                )),
                                signature,
                            };
                            let p = parent_path.clone().at(
                                "entries",
                                EntryHashB64::from(delete.deletes_entry_address.clone())
                                    .to_string(),
                            )?;
                            // .expect("Can't build parent path");

                            match db
                                .fluent()
                                .insert()
                                .into("deletes")
                                .document_id(
                                    ActionHashB64::from(action.action_address().clone())
                                        .to_string(),
                                )
                                .parent(&p)
                                .object(&action)
                                .execute::<SignedActionHashed>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not create record");
                        }
                        DhtOp::StoreRecord(signature, action, record_entry) => {
                            let action = SignedHashed {
                                hashed: HoloHashed::from_content_sync(action.clone()),
                                signature,
                            };

                            match db
                                .fluent()
                                .insert()
                                .into("actions")
                                .document_id(
                                    ActionHashB64::from(action.action_address().clone())
                                        .to_string(),
                                )
                                .parent(&parent_path)
                                .object(&action)
                                .execute::<SignedActionHashed>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not create record");
                        }
                        DhtOp::StoreEntry(signature, new_entry_action, record_entry) => {
                            let action = SignedHashed {
                                hashed: HoloHashed::from_content_sync(Action::from(
                                    new_entry_action.clone(),
                                )),
                                signature,
                            };

                            let document_id =
                                EntryHashB64::from(new_entry_action.entry().clone()).to_string();

                            match db
                                .fluent()
                                .insert()
                                .into("entries")
                                .document_id(document_id.clone())
                                .parent(&parent_path)
                                .object(&record_entry)
                                .execute::<Entry>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not create entry");

                            let p = parent_path.clone().at("entries", document_id.clone())?;
                            // .expect("Could not create parent path");

                            match db
                                .fluent()
                                .insert()
                                .into("creates")
                                .document_id(document_id)
                                .parent(&p)
                                .object(&action)
                                .execute::<SignedActionHashed>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not create entry's record");
                        }
                        DhtOp::RegisterAddLink(signature, create_link) => {
                            let action = SignedHashed {
                                hashed: HoloHashed::from_content_sync(Action::CreateLink(
                                    create_link.clone(),
                                )),
                                signature,
                            };

                            let document_id =
                                AnyLinkableHashB64::from(create_link.base_address.clone())
                                    .to_string();

                            match db
                                .fluent()
                                .insert()
                                .into("links")
                                .document_id(document_id.clone())
                                .parent(&parent_path)
                                .object(&LinkBaseRecord {
                                    base: create_link.base_address.clone(),
                                })
                                .execute::<LinkBaseRecord>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;

                            let p = parent_path.clone().at("links", document_id.clone())?;

                            match db
                                .fluent()
                                .insert()
                                .into("creates")
                                .document_id(
                                    ActionHashB64::from(action.hashed.hash.clone()).to_string(),
                                )
                                .parent(&p)
                                .object(&action)
                                .execute::<SignedActionHashed>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                        }
                        DhtOp::RegisterRemoveLink(signature, delete_link) => {
                            let action = SignedHashed {
                                hashed: HoloHashed::from_content_sync(Action::DeleteLink(
                                    delete_link.clone(),
                                )),
                                signature,
                            };

                            let document_id =
                                AnyLinkableHashB64::from(delete_link.base_address.clone())
                                    .to_string();

                            match db
                                .fluent()
                                .insert()
                                .into("links")
                                .document_id(document_id.clone())
                                .parent(&parent_path)
                                .object(&LinkBaseRecord {
                                    base: delete_link.base_address.clone(),
                                })
                                .execute::<LinkBaseRecord>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not create link base");

                            let p = parent_path.clone().at("links", document_id.clone())?;
                            // .expect("Could not create links path");

                            match db
                                .fluent()
                                .insert()
                                .into("deletes")
                                .document_id(
                                    ActionHashB64::from(action.hashed.hash.clone()).to_string(),
                                )
                                .parent(&p)
                                .object(&action)
                                .execute::<SignedActionHashed>()
                                .await
                            {
                                Ok(_) | Err(FirestoreError::DataConflictError(_)) => Ok(()),
                                Err(err) => Err(HolochainP2pError::Firestore(err)),
                            }?;
                            // .expect("Could not entry's create record");
                        }
                        _ => {}
                    }
                }
            }

            Ok(())
        }
        .boxed()
        .into())

        //     use kitsune_p2p_types::KitsuneTimeout;

        //     let source = source.into_kitsune();
        //     let space = dna_hash.clone().into_kitsune();
        //     let basis = basis_hash.to_kitsune();
        //     let timeout = match timeout_ms {
        //         Some(ms) => KitsuneTimeout::from_millis(ms),
        //         None => self.config.tuning_params.implicit_timeout(),
        //     };

        //     let fetch_context = FetchContext::default()
        //         .with_request_validation_receipt(request_validation_receipt)
        //         .with_countersigning_session(countersigning_session);

        //     let kitsune_p2p = self.kitsune_p2p.clone();
        //     let host = self.host.clone();
        //     let evt_sender = self.evt_sender.clone();
        //     Ok(async move {
        //         if let Some(reflect_ops) = reflect_ops {
        //             let _ = evt_sender
        //                 .publish(
        //                     dna_hash,
        //                     request_validation_receipt,
        //                     countersigning_session,
        //                     reflect_ops,
        //                 )
        //                 .await;
        //         }

        //         // little awkward, but we need the side-effects of reporting
        //         // the context back to the host api here:
        //         if let Err(err) = host
        //             .check_op_data(
        //                 space.clone(),
        //                 op_hash_list.iter().map(|x| x.data()).collect(),
        //                 Some(fetch_context),
        //             )
        //             .await
        //         {
        //             tracing::warn!(?err);
        //         }

        //         kitsune_p2p
        //             .broadcast(
        //                 space.clone(),
        //                 basis.clone(),
        //                 timeout,
        //                 BroadcastData::Publish {
        //                     source,
        //                     op_hash_list,
        //                     context: fetch_context,
        //                 },
        //             )
        //             .await?;
        //         Ok(())
        //     }
        //     .boxed()
        //     .into())
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_publish_countersign(
        &mut self,
        dna_hash: DnaHash,
        flag: bool,
        basis_hash: holo_hash::OpBasis,
        op: DhtOp,
    ) -> HolochainP2pHandlerResult<()> {
        unimplemented!()
        // let space = dna_hash.into_kitsune();
        // let basis = basis_hash.to_kitsune();
        // let timeout = self.config.tuning_params.implicit_timeout();

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(async move {
        //     let payload = crate::wire::WireMessage::publish_countersign(flag, op).encode()?;

        //     kitsune_p2p
        //         .broadcast(space, basis, timeout, BroadcastData::User(payload))
        //         .await?;
        //     Ok(())
        // }
        // .boxed()
        // .into())
    }

    #[tracing::instrument(skip(self, dna_hash, dht_hash, options), level = "trace")]
    fn handle_get(
        &mut self,
        dna_hash: DnaHash,
        dht_hash: holo_hash::AnyDhtHash,
        options: actor::GetOptions,
    ) -> HolochainP2pHandlerResult<Vec<WireOps>> {
        // let space = dna_hash.into_kitsune();
        // let basis = dht_hash.to_kitsune();
        // let r_options: event::GetOptions = (&options).into();

        // let payload = crate::wire::WireMessage::get(dht_hash, r_options).encode()?;

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // let tuning_params = self.config.tuning_params.clone();
        // Ok(async move {
        //     let input = kitsune_p2p::actor::RpcMulti::new(&tuning_params, space, basis, payload);
        //     let result = kitsune_p2p
        //         .rpc_multi(input)
        //         .instrument(tracing::debug_span!("rpc_multi"))
        //         .await?;

        //     let mut out = Vec::new();
        //     for item in result {
        //         let kitsune_p2p::actor::RpcMultiResponse { response, .. } = item;
        //         out.push(SerializedBytes::from(UnsafeBytes::from(response)).try_into()?);
        //     }

        //     Ok(out)
        // }
        // .boxed()
        // .into())
        Ok(async move {
            let db = db().await?;
            let cached_db = cached_db(dna_hash.clone()).await?;
            let parent_path = db.parent_path("dnas", DnaHashB64::from(dna_hash).to_string())?;
            // .expect("Could not build parent path");

            match dht_hash.into_primitive() {
                AnyDhtHashPrimitive::Entry(entry_hash) => {
                    let document_id = EntryHashB64::from(entry_hash).to_string();
                    let mut entry: Option<Entry> = cached_db
                        .fluent()
                        .select()
                        .by_id_in("entries")
                        .parent(&parent_path)
                        .obj()
                        .one(document_id.clone())
                        .await?;
                    // .expect("Could not get entry");

                    let p = parent_path.at("entries", document_id)?;
                    // .expect("Could not build parent path");

                    let page = db
                        .fluent()
                        .list()
                        .from("creates")
                        .parent(&p)
                        .page_size(100_000)
                        .get_page()
                        .await?;
                    let creates: Vec<SignedActionHashed> = page
                        .documents
                        .into_iter()
                        .map(|document| {
                            firestore_document_to_serializable::<SignedActionHashed>(&document)
                        })
                        .collect::<Result<Vec<SignedActionHashed>, FirestoreError>>()?;

                    let page = db
                        .fluent()
                        .list()
                        .from("updates")
                        .parent(&p)
                        .page_size(100_000)
                        .get_page()
                        .await?;
                    let updates: Vec<SignedActionHashed> = page
                        .documents
                        .into_iter()
                        .map(|document| {
                            firestore_document_to_serializable::<SignedActionHashed>(&document)
                        })
                        .collect::<Result<Vec<SignedActionHashed>, FirestoreError>>()?;

                    let page = db
                        .fluent()
                        .list()
                        .from("deletes")
                        .parent(&p)
                        .page_size(100_000)
                        .get_page()
                        .await?;
                    let deletes: Vec<SignedActionHashed> = page
                        .documents
                        .into_iter()
                        .map(|document| {
                            firestore_document_to_serializable::<SignedActionHashed>(&document)
                        })
                        .collect::<Result<Vec<SignedActionHashed>, FirestoreError>>()?;

                    let mut entry_data: Option<EntryData> = None;

                    if let Some(entry) = entry {
                        if let Some(create) = creates.first() {
                            entry_data = Some(EntryData {
                                entry,
                                entry_type: create
                                    .action()
                                    .entry_type()
                                    .cloned()
                                    .expect("Misplaced create"),
                            });
                        }
                    }

                    let wire_entry_ops = WireEntryOps {
                        creates: creates
                            .iter()
                            .cloned()
                            .filter_map(|c| WireNewEntryAction::try_from(c).ok())
                            .map(|c| Judged::valid(c))
                            .collect(),
                        entry: entry_data,
                        deletes: deletes
                            .into_iter()
                            .filter_map(|d| WireDelete::try_from(d).ok())
                            .map(|d| Judged::valid(d))
                            .collect(),
                        updates: updates
                            .into_iter()
                            .filter_map(|d| WireUpdateRelationship::try_from(d).ok())
                            .map(|d| Judged::valid(d))
                            .collect(),
                    };

                    Ok(vec![WireOps::Entry(wire_entry_ops)])
                }
                AnyDhtHashPrimitive::Action(action_hash) => {
                    let document_id = ActionHashB64::from(action_hash).to_string();
                    let action: Option<SignedActionHashed> = cached_db
                        .fluent()
                        .select()
                        .by_id_in("actions")
                        .parent(&parent_path)
                        .obj()
                        .one(document_id.clone())
                        .await?;

                    let mut entry: Option<Entry> = None;

                    if let Some(action) = action.clone() {
                        if let Some(entry_hash) = action.action().entry_hash() {
                            entry = db
                                .fluent()
                                .select()
                                .by_id_in("entries")
                                .parent(&parent_path)
                                .obj()
                                .one(EntryHashB64::from(entry_hash.clone()).to_string())
                                .await?;
                        }
                    }
                    // .expect("Could not get record");
                    let p = parent_path.at("actions", document_id.clone())?;

                    let page = db
                        .fluent()
                        .list()
                        .from("updates")
                        .parent(&p)
                        .page_size(100_000)
                        .get_page()
                        .await?;
                    let updates: Vec<SignedActionHashed> = page
                        .documents
                        .into_iter()
                        .map(|document| {
                            firestore_document_to_serializable::<SignedActionHashed>(&document)
                        })
                        .collect::<Result<Vec<SignedActionHashed>, FirestoreError>>()?;

                    let page = db
                        .fluent()
                        .list()
                        .from("deletes")
                        .parent(&p)
                        .page_size(100_000)
                        .get_page()
                        .await?;
                    let deletes: Vec<SignedActionHashed> = page
                        .documents
                        .into_iter()
                        .map(|document| {
                            firestore_document_to_serializable::<SignedActionHashed>(&document)
                        })
                        .collect::<Result<Vec<SignedActionHashed>, FirestoreError>>()?;

                    let wire_record_ops = WireRecordOps {
                        action: action.clone().map(|a| Judged::valid(a.into())),
                        entry,
                        deletes: deletes
                            .into_iter()
                            .filter_map(|d| WireDelete::try_from(d).ok())
                            .map(|d| Judged::valid(d))
                            .collect(),
                        updates: updates
                            .into_iter()
                            .filter_map(|d| WireUpdateRelationship::try_from(d).ok())
                            .map(|d| Judged::valid(d))
                            .collect(),
                    };

                    Ok(vec![WireOps::Record(wire_record_ops)])
                }
            }
        }
        .boxed()
        .into())
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_get_meta(
        &mut self,
        dna_hash: DnaHash,
        dht_hash: holo_hash::AnyDhtHash,
        options: actor::GetMetaOptions,
    ) -> HolochainP2pHandlerResult<Vec<MetadataSet>> {
        // let space = dna_hash.into_kitsune();
        // let basis = dht_hash.to_kitsune();
        // let r_options: event::GetMetaOptions = (&options).into();

        // let payload = crate::wire::WireMessage::get_meta(dht_hash, r_options).encode()?;

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // let tuning_params = self.config.tuning_params.clone();
        // Ok(async move {
        //     let input = kitsune_p2p::actor::RpcMulti::new(&tuning_params, space, basis, payload);
        //     let result = kitsune_p2p.rpc_multi(input).await?;

        //     let mut out = Vec::new();
        //     for item in result {
        //         let kitsune_p2p::actor::RpcMultiResponse { response, .. } = item;
        //         out.push(SerializedBytes::from(UnsafeBytes::from(response)).try_into()?);
        //     }

        //     Ok(out)
        // }
        // .boxed()
        // .into())
        unimplemented!()
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_get_links(
        &mut self,
        dna_hash: DnaHash,
        link_key: WireLinkKey,
        options: actor::GetLinksOptions,
    ) -> HolochainP2pHandlerResult<Vec<WireLinkOps>> {
        // let space = dna_hash.into_kitsune();
        // let basis = link_key.base.to_kitsune();
        // let r_options: event::GetLinksOptions = (&options).into();

        // let payload = crate::wire::WireMessage::get_links(link_key, r_options).encode()?;

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // let tuning_params = self.config.tuning_params.clone();
        // Ok(async move {
        //     let mut input =
        //         kitsune_p2p::actor::RpcMulti::new(&tuning_params, space, basis, payload);
        //     // NOTE - We're just targeting a single remote node for now
        //     //        without doing any pagination / etc...
        //     //        Setting up RpcMulti to act like RpcSingle
        //     input.max_remote_agent_count = 1;
        //     let result = kitsune_p2p.rpc_multi(input).await?;

        //     let mut out = Vec::new();
        //     for item in result {
        //         let kitsune_p2p::actor::RpcMultiResponse { response, .. } = item;
        //         out.push(SerializedBytes::from(UnsafeBytes::from(response)).try_into()?);
        //     }

        //     Ok(out)
        // }
        // .boxed()
        // .into())

        Ok(async move {
            let db = db().await?;
            let parent_path = db.parent_path("dnas", DnaHashB64::from(dna_hash).to_string())?;
            // .expect("Could not build parent path");
            let document_id = AnyLinkableHashB64::from(link_key.base).to_string();

            let p = parent_path.at("links", document_id)?;
            // .expect("Could not build parent path");

            let page = db
                .fluent()
                .list()
                .from("creates")
                .parent(&p)
                .page_size(100_000)
                .get_page()
                .await?;
            let creates: Vec<SignedActionHashed> = page
                .documents
                .into_iter()
                .map(|document| firestore_document_to_serializable::<SignedActionHashed>(&document))
                .collect::<Result<Vec<SignedActionHashed>, FirestoreError>>()?;

            let all_create_link_hashes: Vec<ActionHash> = creates
                .iter()
                .filter(|c| match c.hashed.content.clone() {
                    Action::CreateLink(cl) => {
                        link_key.type_query.contains(&cl.zome_index, &cl.link_type)
                    }
                    _ => false,
                })
                .map(|r| r.hashed.hash.clone())
                .collect();

            let page = db
                .fluent()
                .list()
                .from("deletes")
                .parent(&p)
                .page_size(100_000)
                .get_page()
                .await?;
            let deletes: Vec<SignedActionHashed> = page
                .documents
                .into_iter()
                .map(|document| firestore_document_to_serializable::<SignedActionHashed>(&document))
                .collect::<Result<Vec<SignedActionHashed>, FirestoreError>>()?;
            // .expect("Could not create stream");

            let wire_links_ops = WireLinkOps {
                creates: creates
                    .into_iter()
                    .filter_map(|c| match c.hashed.content.clone() {
                        Action::CreateLink(cl) => {
                            if !link_key.type_query.contains(&cl.zome_index, &cl.link_type) {
                                return None;
                            }
                            Some(WireCreateLink::condense(
                                cl.clone(),
                                c.signature().clone(),
                                ValidationStatus::Valid,
                            ))
                        }
                        _ => None,
                    })
                    .collect(),
                deletes: deletes
                    .into_iter()
                    .filter(|c| match c.hashed.content.clone() {
                        Action::DeleteLink(dl) => {
                            all_create_link_hashes.contains(&dl.link_add_address)
                        }
                        _ => false,
                    })
                    .filter_map(|c| match c.hashed.content.clone() {
                        Action::DeleteLink(cl) => Some(WireDeleteLink::condense(
                            cl.clone(),
                            c.signature().clone(),
                            ValidationStatus::Valid,
                        )),
                        _ => None,
                    })
                    .collect(),
            };

            Ok(vec![wire_links_ops])
        }
        .boxed()
        .into())
    }

    fn handle_count_links(
        &mut self,
        dna_hash: DnaHash,
        query: WireLinkQuery,
    ) -> HolochainP2pHandlerResult<CountLinksResponse> {
        // let space = dna_hash.into_kitsune();
        // let basis = query.base.to_kitsune();

        // let payload = WireMessage::count_links(query).encode()?;

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // let tuning_params = self.config.tuning_params.clone();
        // Ok(async move {
        //     let mut input =
        //         kitsune_p2p::actor::RpcMulti::new(&tuning_params, space, basis, payload);
        //     input.max_remote_agent_count = 1;
        //     let result = kitsune_p2p.rpc_multi(input).await?;

        //     if let Some(result) = result.into_iter().next() {
        //         let kitsune_p2p::actor::RpcMultiResponse { response, .. } = result;
        //         Ok(SerializedBytes::from(UnsafeBytes::from(response)).try_into()?)
        //     } else {
        //         Err(HolochainP2pError::from(
        //             "Failed to fetch link count from a peer",
        //         ))
        //     }
        // }
        // .boxed()
        // .into())
        unimplemented!()
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_get_agent_activity(
        &mut self,
        dna_hash: DnaHash,
        agent: AgentPubKey,
        query: ChainQueryFilter,
        options: actor::GetActivityOptions,
    ) -> HolochainP2pHandlerResult<Vec<AgentActivityResponse<ActionHash>>> {
        // let space = dna_hash.into_kitsune();
        // // Convert the agent key to an any dht hash so it can be used
        // // as the basis for sending this request
        // let agent_hash: AnyDhtHash = agent.clone().into();
        // let basis = agent_hash.to_kitsune();
        // let r_options: event::GetActivityOptions = (&options).into();

        // let payload =
        //     crate::wire::WireMessage::get_agent_activity(agent, query, r_options).encode()?;

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // let tuning_params = self.config.tuning_params.clone();
        // Ok(async move {
        //     let mut input =
        //         kitsune_p2p::actor::RpcMulti::new(&tuning_params, space, basis, payload);
        //     // TODO - We're just targeting a single remote node for now
        //     //        without doing any pagination / etc...
        //     //        Setting up RpcMulti to act like RpcSingle
        //     input.max_remote_agent_count = 1;
        //     let result = kitsune_p2p.rpc_multi(input).await?;

        //     let mut out = Vec::new();
        //     for item in result {
        //         let kitsune_p2p::actor::RpcMultiResponse { response, .. } = item;
        //         out.push(SerializedBytes::from(UnsafeBytes::from(response)).try_into()?);
        //     }

        //     Ok(out)
        // }
        // .boxed()
        // .into())
        unimplemented!()
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_must_get_agent_activity(
        &mut self,
        dna_hash: DnaHash,
        agent: AgentPubKey,
        filter: holochain_zome_types::chain::ChainFilter,
    ) -> HolochainP2pHandlerResult<Vec<MustGetAgentActivityResponse>> {
        // let space = dna_hash.into_kitsune();
        // // Convert the agent key to an any dht hash so it can be used
        // // as the basis for sending this request
        // let agent_hash: AnyDhtHash = agent.clone().into();
        // let basis = agent_hash.to_kitsune();

        // let payload = crate::wire::WireMessage::must_get_agent_activity(agent, filter).encode()?;

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // let tuning_params = self.config.tuning_params.clone();
        // Ok(async move {
        //     let mut input =
        //         kitsune_p2p::actor::RpcMulti::new(&tuning_params, space, basis, payload);
        //     // TODO - We're just targeting a single remote node for now
        //     //        without doing any pagination / etc...
        //     //        Setting up RpcMulti to act like RpcSingle
        //     input.max_remote_agent_count = 1;
        //     let result = kitsune_p2p.rpc_multi(input).await?;

        //     let mut out = Vec::new();
        //     for item in result {
        //         let kitsune_p2p::actor::RpcMultiResponse { response, .. } = item;
        //         out.push(SerializedBytes::from(UnsafeBytes::from(response)).try_into()?);
        //     }

        //     Ok(out)
        // }
        // .boxed()
        // .into())
        unimplemented!()
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_send_validation_receipts(
        &mut self,
        dna_hash: DnaHash,
        to_agent: AgentPubKey,
        receipts: ValidationReceiptBundle,
    ) -> HolochainP2pHandlerResult<()> {
        // let space = dna_hash.into_kitsune();
        // let to_agent = to_agent.into_kitsune();

        // let req = crate::wire::WireMessage::validation_receipts(receipts).encode()?;

        // let timeout = self.config.tuning_params.implicit_timeout();

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(async move {
        //     kitsune_p2p
        //         .targeted_broadcast(space, vec![to_agent], timeout, req, false)
        //         .await?;
        //     Ok(())
        // }
        // .boxed()
        // .into())
        Ok(async move { Ok(()) }.boxed().into())
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_new_integrated_data(&mut self, dna_hash: DnaHash) -> HolochainP2pHandlerResult<()> {
        // let space = dna_hash.into_kitsune();

        // let kitsune_p2p = self.kitsune_p2p.clone();
        Ok(async move { Ok(()) }.boxed().into())
        // unimplemented!()
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_authority_for_hash(
        &mut self,
        dna_hash: DnaHash,
        basis_hash: OpBasis,
    ) -> HolochainP2pHandlerResult<bool> {
        // let space = dna_hash.into_kitsune();
        // let basis = basis_hash.to_kitsune();

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(
        //     async move { Ok(kitsune_p2p.authority_for_hash(space, basis).await?) }
        //         .boxed()
        //         .into(),
        // )
        Ok(async move { Ok(false) }.boxed().into())
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn handle_countersigning_session_negotiation(
        &mut self,
        dna_hash: DnaHash,
        agents: Vec<AgentPubKey>,
        message: CountersigningSessionNegotiationMessage,
    ) -> HolochainP2pHandlerResult<()> {
        // let space = dna_hash.into_kitsune();
        // let agents = agents.into_iter().map(|a| a.into_kitsune()).collect();

        // let timeout = self.config.tuning_params.implicit_timeout();

        // let payload =
        //     crate::wire::WireMessage::countersigning_session_negotiation(message).encode()?;

        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(async move {
        //     kitsune_p2p
        //         .targeted_broadcast(space, agents, timeout, payload, false)
        //         .await?;
        //     Ok(())
        // }
        // .boxed()
        // .into())
        unimplemented!()
    }

    fn handle_dump_network_metrics(
        &mut self,
        dna_hash: Option<DnaHash>,
    ) -> HolochainP2pHandlerResult<String> {
        unimplemented!()
        // let space = dna_hash.map(|h| h.into_kitsune());
        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(async move {
        //     serde_json::to_string_pretty(&kitsune_p2p.dump_network_metrics(space).await?)
        //         .map_err(HolochainP2pError::other)
        // }
        // .boxed()
        // .into())
    }

    fn handle_dump_network_stats(&mut self) -> HolochainP2pHandlerResult<String> {
        unimplemented!()
        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(async move {
        //     serde_json::to_string_pretty(&kitsune_p2p.dump_network_stats().await?)
        //         .map_err(HolochainP2pError::other)
        // }
        // .boxed()
        // .into())
    }

    fn handle_get_diagnostics(
        &mut self,
        dna_hash: DnaHash,
    ) -> HolochainP2pHandlerResult<KitsuneDiagnostics> {
        unimplemented!()
        // let space = dna_hash.into_kitsune();
        // let kitsune_p2p = self.kitsune_p2p.clone();
        // Ok(async move {
        //     kitsune_p2p
        //         .get_diagnostics(space)
        //         .await
        //         .map_err(HolochainP2pError::other)
        // }
        // .boxed()
        // .into())
    }
}
