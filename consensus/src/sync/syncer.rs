use std::{
    collections::HashSet,
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::BoxFuture, FutureExt, Stream, StreamExt};
use nimiq_block::Block;
use nimiq_blockchain_interface::AbstractBlockchain;
use nimiq_blockchain_proxy::BlockchainProxy;
use nimiq_hash::Blake2bHash;
use nimiq_network_interface::network::{CloseReason, Network, NetworkEvent, SubscribeEvents};
use nimiq_primitives::policy::Policy;
use nimiq_time::{interval, Interval};
use nimiq_utils::stream::FuturesUnordered;

use crate::{
    consensus::ResolveBlockRequest, messages::RequestHead, sync::live::block_queue::BlockSource,
};

/// Trait that defines how a node synchronizes macro blocks
/// The expected functionality is that there could be different methods of syncing but they
/// all must synchronize to the latest macro block. An implementation of this trait requests,
/// process and validates these macro blocks.
/// The quantity of macro blocks needed or extra metadata associated are defined by each
/// implementor of these trait.
pub trait MacroSync<TPeerId>: Stream<Item = MacroSyncReturn<TPeerId>> + Unpin + Send {
    /// The maximum amount of epochs we request for MacroSync
    const MAX_REQUEST_EPOCHS: u16;
    /// Adds a peer to synchronize macro blocks
    fn add_peer(&mut self, peer_id: TPeerId);
}

/// Trait that defines how a node synchronizes receiving the blocks the peers are currently
/// processing.
/// The expected functionality is that there could be different methods of syncing but they
/// all must synchronize to the latest macro block. Once that happened, an implementation of
/// this trait comes into play to start receiving or processing the blocks that the peers are
/// currently processing and/or synchronize micro blocks.
pub trait LiveSync<N: Network>: Stream<Item = LiveSyncEvent<N::PeerId>> + Unpin + Send {
    /// This function will be called each time a Block is received or announced by any of the
    /// peers added into the LiveSync.
    fn push_block(&mut self, block: Block, block_source: BlockSource<N>);
    /// Adds a peer to receive or request blocks from it.
    fn add_peer(&mut self, peer_id: N::PeerId);
    /// Returns the number of peers that are being synced with
    fn num_peers(&self) -> usize;
    /// Returns the list of peers that are being synced with
    fn peers(&self) -> Vec<N::PeerId>;
    /// Returns whether the state sync has finished (or `true` if there is no state sync required)
    fn state_complete(&self) -> bool {
        true
    }
    /// Initiates an attempt to resolve a ResolveBlockRequest.
    fn resolve_block(&mut self, request: ResolveBlockRequest<N>);
    /// The maximum number of blocks a peer can be ahead before it is considered out-of-sync.
    fn acceptance_window_size(&self) -> u32;
}

#[derive(Debug, PartialEq, Eq)]
/// Return type for a `MacroSync`
pub enum MacroSyncReturn<T> {
    /// We have synced to this peer's macro state.
    Good(T),
    /// The peer is behind our own state.
    Outdated(T),
    /// We can't sync with this peer.
    Incompatible(T),
}

#[derive(Clone, Debug)]
/// Enumeration for events emitted by the Live Sync stream
pub enum LiveSyncEvent<TPeerId> {
    /// Events related to received/accepted or rejected blocks
    PushEvent(LiveSyncPushEvent),
    /// Events related to peer qualifications in the sync
    PeerEvent(LiveSyncPeerEvent<TPeerId>),
}

#[derive(Clone, Debug)]
/// Enumeration for the LiveSync stream events related to blocks
pub enum LiveSyncPushEvent {
    /// An announced block has been accepted
    AcceptedAnnouncedBlock(Blake2bHash),
    /// A buffered block has been accepted
    AcceptedBufferedBlock(Blake2bHash, usize),
    /// Missing blocks were received. The vec of all adopted blocks hashes is given here.
    ReceivedMissingBlocks(Vec<Blake2bHash>),
    /// Block was rejected
    /// (this is only returned in *some* cases blocks were rejected)
    RejectedBlock(Blake2bHash),
    /// Chunks have been accepted for the head block
    /// (note that other accepted chunks won't be announced)
    AcceptedChunks(Blake2bHash),
}

#[derive(Clone, Debug)]
/// Enumeration for the LiveSync stream events related to peers
pub enum LiveSyncPeerEvent<TPeerId> {
    /// Peer is in the past (outdated)
    Behind(TPeerId),
    /// Peer is in the future (advanced)
    Ahead(TPeerId),
}

/// Syncer is the main synchronization object inside `Consensus`
/// It has a reference to the main blockchain and network and has two dynamic
/// trait objects:
/// - Macro sync: Synchronizes up to the last macro block
/// - Live Sync: Synchronizes the blockchain to the blocks being processed/announced
///   by the peers.
///
/// These two dynamic trait objects are necessary to implement the different types of
/// synchronization such as: history sync, full sync and light sync.
/// The Syncer handles the interactions between these trait objects, the blockchain and
/// the network.
pub struct Syncer<N: Network, M: MacroSync<N::PeerId>, L: LiveSync<N>> {
    /// Synchronizes the blockchain to the blocks being processed/announced by the peers
    pub live_sync: L,

    /// Synchronizes the blockchain to the latest macro blocks of the peers
    pub macro_sync: M,

    /// A proxy to the blockchain
    blockchain: BlockchainProxy,

    /// A reference to the network
    network: Arc<N>,

    /// A network event subscription
    network_events: SubscribeEvents<N::PeerId>,

    /// The set of peers that macro sync deemed outdated
    outdated_peers: HashSet<N::PeerId>,

    /// The set of peers that macro sync deemed incompatible
    incompatible_peers: HashSet<N::PeerId>,

    /// Interval to regularly check outdated/incompatible peers if they are up-to-date.
    check_interval: Interval,

    /// The ongoing up-to-date checks for incompatible peers.
    pending_checks: FuturesUnordered<BoxFuture<'static, (N::PeerId, bool)>>,

    /// The number of blockchain extensions triggered by block announcements
    accepted_announcements: usize,
}

impl<N: Network, M: MacroSync<N::PeerId>, L: LiveSync<N>> Syncer<N, M, L> {
    const CHECK_INTERVAL: Duration = Duration::from_secs(60);

    pub fn new(
        blockchain: BlockchainProxy,
        network: Arc<N>,
        live_sync: L,
        macro_sync: M,
    ) -> Syncer<N, M, L> {
        let network_events = network.subscribe_events();
        Syncer {
            live_sync,
            macro_sync,
            blockchain,
            network,
            network_events,
            outdated_peers: Default::default(),
            incompatible_peers: Default::default(),
            check_interval: interval(Self::CHECK_INTERVAL),
            pending_checks: Default::default(),
            accepted_announcements: 0,
        }
    }

    pub fn push_block(&mut self, block: Block, block_source: BlockSource<N>) {
        self.live_sync.push_block(block, block_source);
    }

    fn move_peer_into_macro_sync(&mut self, peer_id: N::PeerId) {
        debug!(%peer_id, "Adding peer to macro sync");
        self.macro_sync.add_peer(peer_id);
    }

    pub fn move_peer_into_live_sync(&mut self, peer_id: N::PeerId) {
        debug!(%peer_id, "Adding peer to live sync");
        self.live_sync.add_peer(peer_id);
    }

    pub fn num_peers(&self) -> usize {
        self.live_sync.num_peers()
    }

    pub fn peers(&self) -> Vec<N::PeerId> {
        self.live_sync.peers()
    }

    pub fn accepted_block_announcements(&self) -> usize {
        self.accepted_announcements
    }

    pub fn state_complete(&self) -> bool {
        self.live_sync.state_complete()
    }

    /// Initiates an attempt to resolve a ResolveBlockRequest.
    pub fn resolve_block(&mut self, request: ResolveBlockRequest<N>) {
        self.live_sync.resolve_block(request)
    }

    fn check_outdated_peers(&mut self) {
        for peer_id in mem::take(&mut self.outdated_peers) {
            self.move_peer_into_macro_sync(peer_id);
        }
    }

    fn check_incompatible_peers(&mut self) {
        for peer_id in mem::take(&mut self.incompatible_peers) {
            self.check_incompatible_peer(peer_id);
        }
    }

    fn check_incompatible_peer(&mut self, peer_id: N::PeerId) {
        let blockchain = self.blockchain.clone();
        let network = Arc::clone(&self.network);
        let acceptance_window_size = self.live_sync.acceptance_window_size();

        debug!(%peer_id, "Checking if incompatible peer is in sync");

        let future = async move {
            let synced =
                Self::is_peer_synced(blockchain, network, peer_id, acceptance_window_size).await;
            (peer_id, synced)
        }
        .boxed();

        self.pending_checks.push(future);
    }

    async fn is_peer_synced(
        blockchain: BlockchainProxy,
        network: Arc<N>,
        peer_id: N::PeerId,
        acceptance_window_size: u32,
    ) -> bool {
        // Request the peer's head state.
        // Disconnect the peer if the request fails.
        let head = match network.request(RequestHead {}, peer_id).await {
            Ok(head) => head,
            Err(e) => {
                debug!(%peer_id, ?e, "Head request to incompatible peer failed");
                network.disconnect_peer(peer_id, CloseReason::Other).await;
                return false;
            }
        };

        // Check the peer's head block number. We consider the peer synced if the peer is
        // at most one batch behind us.
        let peer_block_number = head.block_number;
        let peer_batch = Policy::batch_at(peer_block_number);
        let our_block_number = blockchain.read().block_number();
        let our_batch = Policy::batch_at(our_block_number);

        if peer_batch < our_batch.saturating_sub(1) {
            debug!(
                %peer_id,
                peer_batch,
                our_batch,
                "Incompatible peer is in a different batch"
            );
            return false;
        }

        // Check that the peer is not too far ahead.
        if peer_block_number > our_block_number + acceptance_window_size {
            debug!(
                %peer_id,
                peer_block_number,
                our_block_number,
                acceptance_window_size,
                "Incompatible peer is too far ahead"
            );
            return false;
        }

        true
    }

    fn remove_peer(&mut self, peer_id: &N::PeerId) {
        self.outdated_peers.remove(peer_id);
        self.incompatible_peers.remove(peer_id);
    }
}

impl<N: Network, M: MacroSync<N::PeerId>, L: LiveSync<N>> Stream for Syncer<N, M, L> {
    type Item = LiveSyncPushEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        // Poll network events and remove disconnected peers.
        while let Poll::Ready(event) = self.network_events.poll_next_unpin(cx) {
            let event = match event {
                Some(event) => event,
                None => return Poll::Ready(None),
            };
            match event {
                Ok(NetworkEvent::PeerLeft(peer_id)) => self.remove_peer(&peer_id),
                Err(error) => error!(%error, "Syncer lagged receiving network events"),
                _ => {}
            };
        }

        // Poll macro sync and track the peers that it emits.
        while let Poll::Ready(result) = self.macro_sync.poll_next_unpin(cx) {
            match result {
                Some(MacroSyncReturn::Good(peer_id)) => {
                    debug!(%peer_id, "Macro sync returned good peer");
                    self.move_peer_into_live_sync(peer_id);
                }
                Some(MacroSyncReturn::Outdated(peer_id)) => {
                    debug!(%peer_id, "Macro sync returned outdated peer");
                    self.outdated_peers.insert(peer_id);
                }
                Some(MacroSyncReturn::Incompatible(peer_id)) => {
                    debug!(%peer_id, "Macro sync returned incompatible peer");
                    self.check_incompatible_peer(peer_id);
                }
                None => {}
            }
        }

        // Poll live sync and track the peers that it emits.
        while let Poll::Ready(Some(result)) = self.live_sync.poll_next_unpin(cx) {
            match result {
                LiveSyncEvent::PushEvent(push_event) => {
                    if let LiveSyncPushEvent::AcceptedAnnouncedBlock(..) = push_event {
                        self.accepted_announcements = self.accepted_announcements.saturating_add(1);
                    }
                    return Poll::Ready(Some(push_event));
                }
                LiveSyncEvent::PeerEvent(peer_event) => match peer_event {
                    LiveSyncPeerEvent::Behind(peer_id) => {
                        self.outdated_peers.insert(peer_id);
                    }
                    LiveSyncPeerEvent::Ahead(peer_id) => {
                        self.move_peer_into_macro_sync(peer_id);
                    }
                },
            }
        }

        // Re-check all outdated/incompatible peers whenever the interval triggers.
        while self.check_interval.poll_next_unpin(cx).is_ready() {
            self.check_outdated_peers();
            self.check_incompatible_peers();
        }

        // Handle pending incompatible peer checks.
        while let Poll::Ready(Some((peer_id, synced))) = self.pending_checks.poll_next_unpin(cx) {
            if synced {
                if self.blockchain.read().can_enforce_validity_window() {
                    debug!(%peer_id, "Incompatible peer is in sync, moving it to live sync");
                    self.move_peer_into_live_sync(peer_id);
                } else {
                    debug!(%peer_id, "Incompatible peer is in sync, waiting for the validity sync to complete");
                    self.incompatible_peers.insert(peer_id);
                }
            } else {
                self.incompatible_peers.insert(peer_id);
            }
        }

        Poll::Pending
    }
}
