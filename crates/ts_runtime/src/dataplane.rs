use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    sync::Arc,
};

use futures_util::StreamExt;
use kameo::{
    actor::{ActorRef, Spawn},
    message::{Context, Message, StreamMessage},
};
use ts_dataplane::async_tokio::{
    ActivePeers, DiscoBatch, FromOverlay, FromUnderlay, Rx, StunBatch, ToOverlay, ToUnderlay, Tx,
};
use ts_disco_protocol::{Packet, Plaintext};
use ts_packet::PacketMut;
use ts_transport::{DynEndpoint, OverlayTransportId, UnderlayTransportId};
use ts_util::fmt::{AsHexExt, HexCase};

use crate::{
    Error, Task,
    env::Env,
    packetfilter::PacketFilterState,
    peer_tracker::{PeerDb, PeerState},
    route_updater::{PeerRouteUpdate, SelfRouteUpdate},
    src_filter::SourceFilterState,
};

pub struct DataplaneActor {
    dataplane: Arc<ts_dataplane::async_tokio::DataPlane>,
    env: Env,
    /// The node key each WireGuard peer is configured with.
    wg_peers: HashMap<ts_tunnel::PeerId, ts_keys::NodePublicKey>,
}

#[kameo::messages]
impl DataplaneActor {
    #[message]
    pub async fn new_overlay_transport(
        &self,
    ) -> (OverlayTransportId, Tx<FromOverlay>, Rx<ToOverlay>) {
        self.dataplane.new_overlay_transport().await
    }

    #[message]
    pub async fn new_underlay_transport(
        &self,
    ) -> (UnderlayTransportId, Rx<ToUnderlay>, Tx<FromUnderlay>) {
        self.dataplane.new_underlay_transport().await
    }

    /// Send a message directly to an underlay transport, bypassing the routing layer.
    #[message]
    pub async fn send_underlay(
        &self,
        underlay_id: UnderlayTransportId,
        endpoint: DynEndpoint,
        bufs: Vec<PacketMut>,
    ) -> bool {
        self.dataplane
            .send_underlay(underlay_id, endpoint, bufs)
            .await
    }
}

pub type DiscoPacket = yoke::Yoke<&'static Packet<Plaintext>, ts_packet::Packet>;

#[derive(Clone)]
pub struct IncomingDiscoMsg {
    pub transport: UnderlayTransportId,
    pub sender: DynEndpoint,
    pub packet: DiscoPacket,
}

impl Debug for IncomingDiscoMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.packet.get().fmt(f)
    }
}

impl AsRef<Packet<Plaintext>> for IncomingDiscoMsg {
    fn as_ref(&self) -> &Packet<Plaintext> {
        self.packet.get()
    }
}

struct DiscoInternal(DiscoBatch);

#[derive(Debug, Clone)]
#[expect(dead_code)]
pub struct IncomingStunMsg {
    pub transport: UnderlayTransportId,
    pub sender: DynEndpoint,
    pub pkt: ts_packet::Packet,
}

struct StunInternal(StunBatch);

impl kameo::Actor for DataplaneActor {
    type Args = Env;
    type Error = Error;

    async fn on_start(env: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let (dataplane, disco, stun, active_peers) =
            ts_dataplane::async_tokio::DataPlane::new(env.keys.node_keys.clone());

        let dataplane = Arc::new(dataplane);

        slf.attach_stream(
            tokio_stream::wrappers::UnboundedReceiverStream::new(disco).map(DiscoInternal),
            (),
            (),
        );

        slf.attach_stream(
            tokio_stream::wrappers::UnboundedReceiverStream::new(stun).map(StunInternal),
            (),
            (),
        );

        slf.attach_stream(
            tokio_stream::wrappers::WatchStream::new(active_peers),
            (),
            (),
        );

        env.subscribe::<PeerRouteUpdate>(&slf).await?;
        env.subscribe::<SelfRouteUpdate>(&slf).await?;
        env.subscribe::<PacketFilterState>(&slf).await?;
        env.subscribe::<SourceFilterState>(&slf).await?;
        env.subscribe::<Arc<PeerState>>(&slf).await?;

        let task_dataplane = dataplane.clone();

        Task::spawn_link(&slf, async move {
            task_dataplane.run().await;
        })
        .await;

        tracing::trace!("dataplane running");
        env.register(None, &slf).await?;

        Ok(Self {
            dataplane,
            env,
            wg_peers: HashMap::new(),
        })
    }
}

impl Message<StreamMessage<DiscoInternal, (), ()>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<DiscoInternal, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let (transport_id, ep, bufs) = match msg {
            StreamMessage::Next(pkt) => pkt.0,
            _ => return,
        };

        for mut buf in bufs {
            let pkt = tracing::debug_span!(
                "disco_ingest",
                ?transport_id,
                ?ep,
                sender_disco = tracing::field::Empty
            )
            .in_scope::<_, Option<IncomingDiscoMsg>>(|| {
                let pkt = match Packet::from_encrypted_bytes_mut(buf.as_mut()) {
                    Ok(pkt) => pkt,
                    Err(e) => {
                        tracing::error!(error = %e, "parsing disco message:\n{}",
                            buf.iter().hexdump_string(HexCase::Lower)
                        );
                        return None;
                    }
                };

                tracing::Span::current()
                    .record("sender_disco", tracing::field::display(pkt.sender_pubkey()));

                if let Err(e) = pkt.decrypt_in_place(&self.env.keys.disco_keys.private) {
                    tracing::error!(error = %e, "decrypting disco message");
                    return None;
                };

                let pkt = yoke::Yoke::<&'static Packet<Plaintext>, _>::try_attach_to_cart(
                    buf.freeze(),
                    // SAFETY: we just parsed this from the same buffer, so type/version are set correctly.
                    |buf| unsafe { Packet::from_bytes_unchecked(buf) },
                )
                .unwrap();

                let pkt = IncomingDiscoMsg {
                    transport: transport_id,
                    sender: ep.clone(),
                    packet: pkt,
                };

                tracing::trace!(?pkt, "decrypted disco message");

                Some(pkt)
            });

            if let Some(pkt) = pkt {
                self.env.publish_noretain(pkt).await.unwrap();
            }
        }
    }
}

impl Message<StreamMessage<StunInternal, (), ()>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<StunInternal, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let (transport_id, ep, pkts) = match msg {
            StreamMessage::Next(pkt) => pkt.0,
            _ => return,
        };

        for pkt in pkts {
            self.env
                .publish_noretain(IncomingStunMsg {
                    transport: transport_id,
                    pkt: pkt.freeze(),
                    sender: ep.clone(),
                })
                .await
                .unwrap();
        }
    }
}

impl Message<StreamMessage<ActivePeers, (), ()>> for DataplaneActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<ActivePeers, (), ()>,
        ctx: &mut Context<Self, Self::Reply>,
    ) {
        let peers = match msg {
            StreamMessage::Next(pkt) => pkt,
            StreamMessage::Finished(_) => {
                // TODO(npry): apply to all stream msg handlers
                tracing::warn!("active peers stream died, killing dataplane");
                ctx.stop();
                return;
            }
            StreamMessage::Started(_) => {
                return;
            }
        };

        tracing::debug!(active_peers = ?peers, "new active_peers");

        self.env.publish(peers).await.unwrap();
    }
}

impl Message<PeerRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PeerRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        tracing::trace!("applying peer route update");

        let dp = &mut *self.dataplane.inner().await;
        dp.or_out.swap(msg.inner.overlay_out_routes.clone());

        dp.ur_out.table = msg.inner.underlay_routes.clone();
    }
}

impl Message<SelfRouteUpdate> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SelfRouteUpdate, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.or_in.swap(msg.overlay_in_routes.as_ref().clone());
        }

        tracing::trace!("applied self route update");
    }
}

impl Message<PacketFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: PacketFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.packet_filter = msg.0;
        }

        tracing::trace!("applied new packet filter");
    }
}

impl Message<SourceFilterState> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: SourceFilterState, _ctx: &mut Context<Self, Self::Reply>) {
        {
            let dp = &mut *self.dataplane.inner().await;
            dp.src_filter_in = msg.0;
        }

        tracing::trace!("applied new source filter");
    }
}

impl Message<Arc<PeerState>> for DataplaneActor {
    type Reply = ();

    async fn handle(&mut self, msg: Arc<PeerState>, _ctx: &mut Context<Self, Self::Reply>) {
        // Worked out before taking the dataplane lock, which packets wait on; most peer updates
        // change no WireGuard key.
        let changes = WireguardChanges::new(&msg.peers, &self.wg_peers);
        if changes.is_empty() {
            return;
        }

        changes.apply(
            &mut self.dataplane.inner().await.wireguard,
            &mut self.wg_peers,
        );

        tracing::trace!("applied new peer state");
    }
}

/// What brings WireGuard in line with the peer db.
///
/// It works from the whole db rather than an update's upserts and deletions: the bus keeps only
/// the newest peer state for a subscriber that falls behind.
#[derive(Debug, Default, PartialEq, Eq)]
struct WireguardChanges {
    remove: Vec<ts_tunnel::PeerId>,
    upsert: Vec<(ts_tunnel::PeerId, ts_keys::NodePublicKey)>,
}

impl WireguardChanges {
    fn new(db: &PeerDb, installed: &HashMap<ts_tunnel::PeerId, ts_keys::NodePublicKey>) -> Self {
        // A node key goes to the peer the key index names: while a key is handed over, the db can
        // briefly hold it on two records, and WireGuard keeps one peer per key.
        let want = db
            .iter()
            .filter(|(id, node)| {
                db.get(&node.node_key)
                    .is_some_and(|(holder, _)| holder == *id)
            })
            .map(|(id, node)| (ts_tunnel::PeerId(id.0), node.node_key))
            .collect::<HashMap<_, _>>();

        let remove = installed
            .iter()
            .filter(|&(id, key)| want.get(id) != Some(key))
            .map(|(&id, _)| id)
            .collect();
        let upsert = want
            .into_iter()
            .filter(|(id, key)| installed.get(id) != Some(key))
            .collect();

        Self { remove, upsert }
    }

    fn is_empty(&self) -> bool {
        self.remove.is_empty() && self.upsert.is_empty()
    }

    fn apply(
        self,
        wg: &mut ts_tunnel::Endpoint,
        installed: &mut HashMap<ts_tunnel::PeerId, ts_keys::NodePublicKey>,
    ) {
        // Removals first: a node key a removed peer held may now belong to another one.
        for id in self.remove {
            wg.remove_peer(id);
            installed.remove(&id);
        }

        for (id, key) in self.upsert {
            wg.upsert_peer(ts_tunnel::PeerConfig::new(id, key, [0u8; 32]));
            installed.insert(id, key);
        }
    }
}

#[cfg(test)]
mod test {
    use ts_control::NodeUpdate;
    use ts_keys::{NodeKeyPair, NodePublicKey};

    use super::*;
    use crate::peer_tracker::test_node;

    fn sync(
        db: &PeerDb,
        wg: &mut ts_tunnel::Endpoint,
        installed: &mut HashMap<ts_tunnel::PeerId, NodePublicKey>,
    ) {
        WireguardChanges::new(db, installed).apply(wg, installed);
        for (id, key) in installed.iter() {
            assert_eq!(wg.peer_key(*id), Some(*key), "cached peer not installed");
        }
    }

    #[test]
    fn a_node_key_handed_over_stays_with_its_new_holder_after_the_old_one_goes() {
        // The old code depended on hash order, so a run covers many orders.
        for _ in 0..32 {
            let mut wg = ts_tunnel::Endpoint::new(NodeKeyPair::random());
            let mut installed = HashMap::new();

            let old = test_node();
            let new = test_node();
            let mut db = PeerDb::default();
            let old_id = db.upsert(&old);
            let new_id = db.upsert(&new);
            sync(&db, &mut wg, &mut installed);

            // The new holder takes the key before control rotates or removes the old one.
            db.patch(&NodeUpdate {
                id: new.id,
                node_key: Some(old.node_key),
                ..Default::default()
            });
            sync(&db, &mut wg, &mut installed);
            assert_eq!(wg.peer_id(old.node_key), Some(ts_tunnel::PeerId(new_id.0)));

            db.remove(&old_id);
            sync(&db, &mut wg, &mut installed);
            assert_eq!(wg.peer_id(old.node_key), Some(ts_tunnel::PeerId(new_id.0)));
            assert_eq!(wg.peer_key(ts_tunnel::PeerId(old_id.0)), None);
        }
    }

    #[test]
    fn an_update_that_changes_no_key_changes_nothing() {
        let mut db = PeerDb::default();
        let node = test_node();
        db.upsert(&node);

        let mut wg = ts_tunnel::Endpoint::new(NodeKeyPair::random());
        let mut installed = HashMap::new();
        sync(&db, &mut wg, &mut installed);

        db.patch(&NodeUpdate {
            id: node.id,
            underlay_addresses: Some(vec!["192.0.2.1:41641".parse().unwrap()]),
            ..Default::default()
        });
        assert!(WireguardChanges::new(&db, &installed).is_empty());
    }
}
