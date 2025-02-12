use std::{
    collections::BTreeMap,
    sync::Arc,
    task::{Context, Poll},
};

use futures::StreamExt;
use nimiq_blockchain::{interface::HistoryInterface, Blockchain, CHUNK_SIZE};
use nimiq_blockchain_interface::AbstractBlockchain;
use nimiq_blockchain_proxy::BlockchainProxy;
use nimiq_hash::Blake2bHash;
use nimiq_network_interface::{
    network::{CloseReason, Network},
    request::RequestError,
};
use nimiq_primitives::policy::Policy;
use nimiq_transaction::historic_transaction::HistoricTransaction;

use super::LightMacroSync;
use crate::{
    messages::{HistoryChunk, HistoryChunkError, RequestHistoryChunk},
    sync::{light::sync::ValidityChunkRequest, syncer::MacroSyncReturn},
};

impl<TNetwork: Network> LightMacroSync<TNetwork> {
    pub async fn request_validity_window_chunk(
        network: Arc<TNetwork>,
        peer_id: TNetwork::PeerId,
        epoch_number: u32,
        block_number: u32,
        chunk_index: u64,
    ) -> Result<Result<HistoryChunk, HistoryChunkError>, RequestError> {
        // A validity window chunk is simply a history chunk
        network
            .request::<RequestHistoryChunk>(
                RequestHistoryChunk {
                    epoch_number,
                    block_number,
                    chunk_index,
                },
                peer_id,
            )
            .await
    }

    fn start_validity_chunk_request(
        &mut self,
        peer_id: TNetwork::PeerId,
        mut verifier_block_number: u32,
        expected_root: Blake2bHash,
        validity_window_start: u32,
        mut election_in_window: bool,
    ) {
        // By default we set the parameters assuming we are starting from the beginning of the epoch.
        let mut epoch_number = Policy::epoch_at(verifier_block_number);
        let mut chunk_index = 0;
        let mut root_hash = expected_root.clone();
        let mut last_chunk_items: Option<usize> = None;

        let blockchain = match &self.blockchain {
            BlockchainProxy::Full(blockchain) => blockchain,
            BlockchainProxy::Light(_) => unreachable!(),
        };

        let blockchain_wr = blockchain.read();

        // First we need to check if we already have items in the history store, and request only the remaining portion (if any)
        let (first_bn, last_bn) = blockchain_wr.history_store.history_store_range(None);

        // This means we already have items for the first epoch of the validity window we are interested in
        // so we need to move to the next epoch to request the missing items.
        if last_bn >= verifier_block_number {
            epoch_number = Policy::epoch_at(last_bn);

            // This length is based on number of leaves in the tree
            let current_length = blockchain_wr
                .history_store
                .length_at(last_bn, None)
                .expect("We must have items in the history store at this height")
                as usize;

            log::debug!(
                first_bn = first_bn,
                last_bn = last_bn,
                current_items = current_length,
                "We already have items in our history store, moving to the current epoch",
            );

            chunk_index = (current_length / CHUNK_SIZE) as u32;
            last_chunk_items = Some(current_length % CHUNK_SIZE);
            root_hash = blockchain_wr.macro_head().header.history_root.clone();
            verifier_block_number = blockchain_wr.macro_head().block_number();
            election_in_window = false;
        } else if last_bn >= validity_window_start {
            // This is the case where we already have items in the start of the validity window
            // We need to request the missing items
            epoch_number = Policy::epoch_at(last_bn);

            // This length is based on number of leaves in the tree
            let current_length = blockchain_wr
                .history_store
                .length_at(last_bn, None)
                .expect("We must have items in the history store at this height")
                as usize;

            log::debug!(
                first_bn = first_bn,
                last_bn = last_bn,
                current_items = current_length,
                "We already have items in our history store",
            );

            chunk_index = (current_length / CHUNK_SIZE) as u32;
            last_chunk_items = Some(current_length % CHUNK_SIZE);
        }

        // Request the macro chain at this height to know the history tree length at this height

        self.validity_requests = Some(ValidityChunkRequest {
            verifier_block_number,
            root_hash,
            chunk_index,
            election_in_window,
            last_chunk_items,
        });

        // Add the peer
        self.validity_queue.add_peer(peer_id);
        self.syncing_peers.insert(peer_id);

        let request = RequestHistoryChunk {
            epoch_number,
            block_number: verifier_block_number,
            chunk_index: chunk_index as u64,
        };

        log::info!(
            target_macro = verifier_block_number,
            chunk_index = chunk_index,
            last_chunk_items = last_chunk_items,
            epoch = epoch_number,
            validity_start = validity_window_start,
            election_in_between = election_in_window,
            expected_root = %expected_root,
            "Starting validity window synchronization process"
        );

        // Request the chunk
        self.validity_queue.add_ids(vec![(request, None)]);
    }

    pub fn start_validity_synchronization(&mut self, peer_id: TNetwork::PeerId) {
        if self.validity_requests.is_some() {
            // We already have a synchoronization in progress, so we just add the peer
            let current_chunk = self.validity_requests.as_ref().unwrap().chunk_index;
            log::debug!(%peer_id,current_chunk,"Adding peer to existing validity synchronization process");
            self.validity_queue.add_peer(peer_id);
            self.syncing_peers.insert(peer_id);
            return;
        }

        let macro_head = self.blockchain.read().macro_head().header.clone();

        let validity_start = macro_head
            .block_number
            .saturating_sub(Policy::transaction_validity_window_blocks());

        let validity_window_bn = if validity_start <= Policy::genesis_block_number() {
            Policy::genesis_block_number()
        } else {
            // We move the validity window to the beginning of the epoch for simplicity reasons.
            // There are two possible cases:
            // A - The validity window is contained in the current epoch
            // B - The validity window spans across the previous epoch and the current one
            //
            // For case A we move the validity window to the beginning of the epoch because
            // apart from syncing the window, we also want to be able to verify the history root
            // of blocks that belong to the current epoch; by doing the latter we can also verify the former.
            //
            // For case B it is not necessary to move the validity window to the beginning of the previous
            // epoch because we already have an election block that can be used to proof txns within the
            // previous epoch, but, for simplicity reasons we decided to still move it because otherwise
            // we would need to start at a specific chunk of the previous epoch and consequently we will need a proof
            // that the server is not omiting or adding information when starting from any chunk index.
            Policy::election_block_before(validity_start)
        };

        // This must correspond to a macro block.
        assert!(Policy::is_macro_block_at(validity_window_bn));

        log::trace!(
            macro_head = macro_head.block_number,
            validity_start = validity_window_bn,
            "Starting a new validity synchronization process"
        );

        let next_election = Policy::election_block_after(validity_window_bn);

        // Now we determine which is the right root and block number to verify the first chunks
        let (verifier_block_number, expected_root, election_in_window) =
            if next_election < macro_head.block_number {
                // This is the case where we are crossing an election block
                let election = self
                    .blockchain
                    .read()
                    .get_block_at(next_election, false)
                    .unwrap();

                (next_election, election.history_root().clone(), true)
            } else {
                // We don't have any election in between so we use the macro head
                (macro_head.block_number, macro_head.history_root, false)
            };

        self.start_validity_chunk_request(
            peer_id,
            verifier_block_number,
            expected_root,
            validity_window_bn,
            election_in_window,
        );
    }

    /// Process the history chunks that are received as part of the validity window synchronization process
    /// Each time a history chunk is received, it is verified and the history store is updated.
    pub fn poll_validity_window_chunks(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<MacroSyncReturn<TNetwork::PeerId>>> {
        while let Poll::Ready(Some(Ok((request, result, peer_id)))) =
            self.validity_queue.poll_next_unpin(cx)
        {
            log::trace!(%peer_id, chunk_index=request.chunk_index, block_number=request.block_number,  "Processing response from validity queue");

            match result {
                Ok(chunk) => {
                    let peer_request = self.validity_requests.as_mut().unwrap();
                    let expected_root = peer_request.root_hash.clone();
                    let mut verifier_block_number = peer_request.verifier_block_number;

                    let leaf_index = peer_request.chunk_index * (CHUNK_SIZE as u32);
                    let chunk = chunk.chunk;

                    log::info!(
                        chunk_index = peer_request.chunk_index,
                        chunk_size = chunk.history.len(),
                        target_macro = verifier_block_number,
                        "Applying a new history chunk"
                    );

                    // Verify the history chunk
                    let valid_chunk = chunk
                        .verify(&expected_root, leaf_index as usize)
                        .is_some_and(|result| result);

                    if !valid_chunk {
                        // If the chunk doesn't verify we disconnect from the peer
                        log::warn!(%peer_id,
                            chunk=request.chunk_index,
                            verifier_block=request.block_number,
                            epoch=request.epoch_number,
                            %expected_root,
                            "Banning peer because the history chunk didn't verify");

                        // For debug purposes we print a summary of the chunk contents
                        let mut txns_per_block: BTreeMap<u32, Vec<HistoricTransaction>> =
                            BTreeMap::new();

                        for txn in chunk.history {
                            txns_per_block
                                .entry(txn.block_number)
                                .or_default()
                                .push(txn.clone());
                        }

                        log::debug!("Invalid chunk contents: ");
                        for (bn, hist_txs) in txns_per_block {
                            debug!(block = bn, num_transactions = hist_txs.len());
                        }

                        // Remove the peer from the syncing process
                        self.validity_queue.remove_peer(&peer_id);
                        self.syncing_peers.remove(&peer_id);

                        // Disconnect and ban the peer
                        self.disconnect_peer(peer_id, CloseReason::MaliciousPeer);

                        // Re add the request to the sync queue
                        self.validity_queue.add_ids(vec![(request, None)]);

                        break;
                    }

                    let blockchain = match &self.blockchain {
                        BlockchainProxy::Full(blockchain) => blockchain,
                        BlockchainProxy::Light(_) => unreachable!(),
                    };

                    let mut epoch_complete = {
                        // We need to check if there were previous items that belong to this chunk
                        let prev_items = peer_request.last_chunk_items.take().unwrap_or(0);

                        // First we calculate the beginning of the chunk that we want to apply
                        let starting_index = match prev_items.cmp(&chunk.history.len()) {
                            std::cmp::Ordering::Less => {
                                // If the chunk has new history items, we need to apply the delta
                                prev_items
                            }
                            std::cmp::Ordering::Equal => {
                                // If we recieved the same chunk (i.e nothing changed) we don't need to re-apply it
                                // So we set the start as the chunk length to apply an empty slice.
                                chunk.history.len()
                            }
                            std::cmp::Ordering::Greater => 0,
                        };

                        let history_root = Blockchain::extend_validity_sync(
                            blockchain.upgradable_read(),
                            &chunk.history[starting_index..],
                        );

                        history_root == expected_root
                    };

                    // Get ready for requesting the next chunk
                    let mut chunk_index = peer_request.chunk_index + 1;

                    // We need to check the latest macro head.
                    let (latest_macro_head_number, latest_history_root) = {
                        let blockchain = self.blockchain.read();
                        let macro_head = blockchain.macro_head();
                        (
                            macro_head.block_number(),
                            macro_head.header.history_root.clone(),
                        )
                    };

                    if latest_macro_head_number > verifier_block_number {
                        // A new macro head was adopted.
                        // TODO: We could keep track of the latest macro heads on a per peer basis
                        //  because not all peers have the latest state.
                        if Policy::epoch_at(verifier_block_number)
                            < Policy::epoch_at(latest_macro_head_number)
                        {
                            if !peer_request.election_in_window {
                                // If the new macro head belongs to the next epoch, we still need to finish syncing the current epoch.
                                log::debug!(
                                    new_macro_head = latest_macro_head_number,
                                    new_epoch = Policy::epoch_at(latest_macro_head_number),
                                    "We have a new macro head that belongs to the next epoch"
                                );
                                peer_request.election_in_window = true;
                            }
                        } else {
                            log::debug!(new_macro_head=latest_macro_head_number, new_history_root=%latest_history_root, current_epoch = Policy::epoch_at(latest_macro_head_number), "We have a new macro head, updating the validity sync target for our current epoch");
                            verifier_block_number = latest_macro_head_number;
                            peer_request.root_hash = latest_history_root.clone();
                            peer_request.verifier_block_number = latest_macro_head_number;

                            // We re-request the same chunk because applying a new macro head could potentially change the number of chunk items.
                            chunk_index = peer_request.chunk_index;
                            peer_request.last_chunk_items = Some(chunk.history.len());

                            // We are no longer complete
                            epoch_complete = false;
                        }
                    }

                    if epoch_complete {
                        // We need to check if there was an election in between, if so, we need to proceed to the next epoch
                        if peer_request.election_in_window {
                            log::trace!(
                                current_epoch = Policy::epoch_at(verifier_block_number),
                                new_verifier_bn = latest_macro_head_number,
                                new_expected_root = %latest_history_root,
                                next_epoch = Policy::epoch_at(latest_macro_head_number),
                                "Moving to the next epoch to continue validity syncing",
                            );

                            // Move to the next epoch:
                            // Note, when we move to the next epoch, we always select the latest macro head as our target
                            verifier_block_number = latest_macro_head_number;
                            chunk_index = 0;
                            peer_request.election_in_window = false;
                            peer_request.root_hash = latest_history_root.clone();
                            peer_request.verifier_block_number = latest_macro_head_number;
                        } else {
                            // We are done
                            log::info!(
                                synced_root = %expected_root,
                                synced_macro_head = verifier_block_number,
                                "Validity window syncing is complete"
                            );

                            self.synced_validity_peers.push(peer_id);
                            self.validity_queue.remove_peer(&peer_id);
                            self.syncing_peers.remove(&peer_id);

                            // We move all the peers from the sync queue to the synced peers.
                            for peer_id in self.syncing_peers.iter() {
                                self.synced_validity_peers.push(*peer_id);
                                self.validity_queue.remove_peer(peer_id);
                            }

                            // We are complete so we emit the peer
                            self.validity_requests = None;
                            self.syncing_peers.clear();
                            break;
                        }
                    }

                    // Update the peer tracker structure
                    peer_request.chunk_index = chunk_index;

                    let request = RequestHistoryChunk {
                        epoch_number: Policy::epoch_at(verifier_block_number),
                        block_number: verifier_block_number,
                        chunk_index: chunk_index as u64,
                    };

                    log::trace!(
                        verifier_bn = verifier_block_number,
                        epoch_number = Policy::epoch_at(verifier_block_number),
                        chunk_index = chunk_index,
                        "Adding a new validity window chunk request"
                    );

                    self.validity_queue.add_ids(vec![(request, None)]);
                }
                Err(err) => {
                    if request.epoch_number == 0 {
                        // A proof cannot be produced for epoch 0, so we emit the peer
                        return Poll::Ready(Some(MacroSyncReturn::Good(peer_id)));
                    }
                    {
                        log::warn!(%err, %peer_id, chunk_index=request.chunk_index,block_number=request.block_number,"The peer could not provide the requested history chunk, we emit it as outdated");

                        // Remove the peer from the syncing process
                        self.validity_queue.remove_peer(&peer_id);
                        self.syncing_peers.remove(&peer_id);

                        // Re add the request to the sync queue
                        self.validity_queue.add_ids(vec![(request, None)]);

                        return Poll::Ready(Some(MacroSyncReturn::Outdated(peer_id)));
                    }
                }
            }
        }

        Poll::Pending
    }
}
