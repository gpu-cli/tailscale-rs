use alloc::collections::BTreeMap;

use bytes::Bytes;
use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncReadExt};
use ts_control_serde::{MapRequest, MapResponse, PingRequest};
use ts_http_util::{BytesBody, ClientExt, Http2, ResponseExt};
use ts_packet::PacketMut;
use ts_packetfilter as pf;
use ts_packetfilter_state as pf_state;
use url::Url;

use crate::{DialPlan, NodeId, NodeStatus};

#[derive(Debug, thiserror::Error, Clone, Copy, Eq, PartialEq)]
pub enum MapStreamError {
    #[error("serialization error")]
    SerDe,
    #[error("unsuccessful HTTP request or upgrade")]
    Http,
    #[error("Network error")]
    NetworkError,
}

impl From<serde_json::Error> for MapStreamError {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "serialization error sending map request");
        MapStreamError::SerDe
    }
}

impl From<ts_http_util::Error> for MapStreamError {
    fn from(error: ts_http_util::Error) -> Self {
        tracing::error!(%error, "http error sending map request");

        if crate::http_error_is_recoverable(error) {
            MapStreamError::NetworkError
        } else {
            MapStreamError::Http
        }
    }
}

impl From<MapStreamError> for crate::Error {
    fn from(e: MapStreamError) -> Self {
        match e {
            MapStreamError::SerDe => crate::Error::Internal(
                crate::InternalErrorKind::SerDe,
                crate::Operation::MapRequest,
            ),
            MapStreamError::Http => {
                crate::Error::Internal(crate::InternalErrorKind::Http, crate::Operation::MapRequest)
            }
            MapStreamError::NetworkError => {
                crate::Error::NetworkError(crate::Operation::MapRequest)
            }
        }
    }
}

/// An update to the peers recorded in the netmap.
#[derive(Debug)]
pub enum PeerUpdate {
    /// Complete peer state.
    Full(Vec<crate::Node>),

    /// Delta update to the peer state.
    Delta {
        /// Peers with a few changed fields in the state.
        patch: Vec<crate::NodeUpdate>,
        /// Peers added to or completely changed in the state.
        upsert: Vec<crate::Node>,
        /// Peer [`NodeId`]s removed from the state.
        remove: Vec<NodeId>,
    },
}

/// The components of a packet filter update.
///
/// These can't be merged into a single map due to the update rules.
pub type FilterUpdate = (Option<pf::Ruleset>, BTreeMap<String, Option<pf::Ruleset>>);

/// An update to the netmap state produced from a mapresponse.
#[derive(Debug)]
pub struct StateUpdate {
    /// New derp map is available.
    pub derp: Option<crate::DerpMap>,
    /// New self-node.
    pub node: Option<crate::Node>,
    /// Updates to the set of peers in the netmap.
    pub peer_update: Option<PeerUpdate>,
    /// Send a ping request.
    pub ping: Option<PingRequest>,
    /// Update to the packet filter.
    pub packetfilter: Option<FilterUpdate>,
    /// This URL should be displayed to the user or opened in their browser automatically.
    pub pop_browser_url: Option<Url>,
    /// New dial plan sent by control.
    pub dial_plan: Option<DialPlan>,
}

/// Read a stream of netmap responses from `reader`, converting them into `StateUpdate`s.
///
/// A stream's first netmap (its first response with the node; a keepalive may come
/// ahead of it) is a whole one: one that names no peers says the tailnet has none
/// (control omits an empty `Peers`), so it is a full, empty peer update rather than no
/// update, and a caller waiting for the peer list is answered.
pub fn map_stream(reader: impl AsyncRead + Unpin) -> impl Stream<Item = StateUpdate> {
    futures_util::stream::unfold((reader, true), async |(mut reader, awaiting_netmap)| {
        let msg_len = reader
            .read_u32_le()
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "could not read netmap length");
            })
            .ok()?;

        let mut buf = PacketMut::new(msg_len as usize);
        tracing::trace!(?msg_len, "reading netmap");

        reader
            .read_exact(buf.as_mut())
            .await
            .inspect_err(|e| {
                tracing::error!(error = %e, "could not read netmap");
            })
            .ok()?;

        let map_response: MapResponse = serde_json::from_slice(buf.as_ref())
            .inspect_err(|e| {
                tracing::error!(error = %e, "deserializing netmap");
            })
            .ok()?;

        tracing::trace!(?msg_len, ?map_response);

        let packetfilter = packet_filter(&map_response);
        // A keepalive or other partial response ahead of the netmap leaves it awaited.
        let still_awaiting = awaiting_netmap && map_response.node.is_none();

        fn nonempty<T>(x: &Option<Vec<T>>) -> bool {
            x.as_ref().is_some_and(|x| !x.is_empty())
        }

        let peer_update = if let Some(full_map) = map_response.peers {
            Some(PeerUpdate::Full(full_map.iter().map(Into::into).collect()))
        } else if nonempty(&map_response.peers_removed)
            || nonempty(&map_response.peers_changed)
            || !map_response.peer_seen_change.is_empty()
            || !map_response.online_change.is_empty()
            || nonempty(&map_response.peers_changed_patch)
        {
            let mut updates: BTreeMap<NodeId, crate::NodeUpdate> = BTreeMap::new();
            for (id, seen) in map_response.peer_seen_change {
                let status = if seen {
                    // Not online, and no timestamp provided by control, so we have to estimate.
                    NodeStatus::new(Some(false), None)
                } else {
                    // We don't know whether the node is online or offline from this field.
                    NodeStatus::Unknown
                };
                updates
                    .entry(id)
                    .and_modify(|u| u.status = status)
                    .or_insert(crate::NodeUpdate {
                        id,
                        status,
                        ..Default::default()
                    });
            }

            for (id, online) in map_response.online_change {
                let status = NodeStatus::new(Some(online), None);
                updates
                    .entry(id)
                    .and_modify(|u| u.status = status)
                    .or_insert(crate::NodeUpdate {
                        id,
                        status,
                        ..Default::default()
                    });
            }

            let mut patches = map_response
                .peers_changed_patch
                .unwrap_or_default()
                .iter()
                .map(|x| (x.node_id, crate::NodeUpdate::from(x)))
                .collect();
            updates.append(&mut patches);

            Some(PeerUpdate::Delta {
                patch: updates.values().cloned().collect(),
                remove: map_response.peers_removed.unwrap_or_default(),
                upsert: map_response
                    .peers_changed
                    .unwrap_or_default()
                    .iter()
                    .map(Into::into)
                    .collect(),
            })
        } else if awaiting_netmap && map_response.node.is_some() {
            Some(PeerUpdate::Full(Vec::new()))
        } else {
            None
        };

        Some((
            StateUpdate {
                peer_update,
                node: map_response.node.as_ref().map(Into::into),
                derp: map_response
                    .derp_map
                    .as_ref()
                    .map(|x| crate::convert_derp_map(x).collect()),
                ping: map_response.ping_request,
                packetfilter,
                pop_browser_url: map_response.pop_browser_url.and_then(|u| {
                    u.parse()
                        .inspect_err(|e| tracing::error!(error = %e, "invalid pop browser url"))
                        .ok()
                }),
                dial_plan: map_response.control_dial_plan.map(Into::into),
            },
            (reader, still_awaiting),
        ))
    })
}

fn packet_filter(map_response: &MapResponse<'_>) -> Option<FilterUpdate> {
    if map_response.packet_filter.is_none() && map_response.packet_filters.is_empty() {
        return None;
    }

    Some((
        map_response
            .packet_filter
            .as_ref()
            .map(|x| pf_state::rules_to_pf(x).collect()),
        map_response
            .packet_filters
            .iter()
            .map(|(rule_name, rules)| {
                (
                    rule_name.to_string(),
                    rules
                        .as_ref()
                        .map(|x| Some(pf_state::rules_to_pf(x).collect()))
                        .unwrap_or_default(),
                )
            })
            .collect(),
    ))
}

/// Send a [`MapRequest`] on the given HTTP2 connection.
#[tracing::instrument(skip_all, fields(map_url = %url.as_str()))]
pub async fn send_map_request(
    map_request: MapRequest<'_>,
    url: &Url,
    http2_conn: &Http2<BytesBody>,
) -> Result<impl AsyncRead + 'static + use<>, MapStreamError> {
    tracing::debug!("sending map request to control server...");

    let body = if cfg!(debug_assertions) {
        serde_json::to_string_pretty(&map_request)?
    } else {
        serde_json::to_string(&map_request)?
    };
    tracing::trace!(
        %body,
        "sending map request"
    );

    let resp = http2_conn.post(url, None, Bytes::from(body).into()).await?;

    let status = resp.status();
    tracing::trace!(?status, "received map response");

    if !status.is_success() {
        tracing::error!(
            status = status.as_u16(),
            "failed to register map updates with unsuccessful HTTP status code"
        );
        return Err(MapStreamError::Http);
    }

    Ok(resp.into_read())
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;

    const NODE: &str = include_str!("../../../ts_control_serde/tests/data/node.json");

    /// The length-prefixed frames a map stream carries.
    fn frames(bodies: &[String]) -> std::io::Cursor<Vec<u8>> {
        let mut out = Vec::new();
        for body in bodies {
            out.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            out.extend_from_slice(body.as_bytes());
        }
        std::io::Cursor::new(out)
    }

    #[tokio::test]
    async fn a_first_netmap_without_peers_is_a_full_empty_peer_update() {
        let first = format!("{{\"Node\": {NODE}}}");
        let updates: Vec<StateUpdate> = map_stream(frames(&[first])).collect().await;
        assert_eq!(updates.len(), 1);
        assert!(
            matches!(&updates[0].peer_update, Some(PeerUpdate::Full(peers)) if peers.is_empty()),
            "{:?}",
            updates[0].peer_update
        );
    }

    #[tokio::test]
    async fn a_later_response_without_peers_leaves_the_peers_as_they_are() {
        let with_node = format!("{{\"Node\": {NODE}}}");
        let updates: Vec<StateUpdate> =
            map_stream(frames(&[with_node.clone(), with_node, "{}".to_owned()]))
                .collect()
                .await;
        assert_eq!(updates.len(), 3);
        assert!(
            updates[1].peer_update.is_none(),
            "{:?}",
            updates[1].peer_update
        );
        assert!(
            updates[2].peer_update.is_none(),
            "{:?}",
            updates[2].peer_update
        );
    }

    #[tokio::test]
    async fn a_first_response_without_the_node_is_not_taken_for_a_netmap() {
        let updates: Vec<StateUpdate> = map_stream(frames(&["{}".to_owned()])).collect().await;
        assert_eq!(updates.len(), 1);
        assert!(
            updates[0].peer_update.is_none(),
            "{:?}",
            updates[0].peer_update
        );
    }

    #[tokio::test]
    async fn a_keepalive_ahead_of_the_netmap_leaves_the_netmap_its_empty_peer_update() {
        let keepalive = "{\"KeepAlive\": true}".to_owned();
        let netmap = format!("{{\"Node\": {NODE}}}");
        let updates: Vec<StateUpdate> = map_stream(frames(&[keepalive.clone(), netmap, keepalive]))
            .collect()
            .await;
        assert_eq!(updates.len(), 3);
        assert!(
            updates[0].peer_update.is_none(),
            "{:?}",
            updates[0].peer_update
        );
        assert!(
            matches!(&updates[1].peer_update, Some(PeerUpdate::Full(peers)) if peers.is_empty()),
            "{:?}",
            updates[1].peer_update
        );
        assert!(
            updates[2].peer_update.is_none(),
            "{:?}",
            updates[2].peer_update
        );
    }
}
