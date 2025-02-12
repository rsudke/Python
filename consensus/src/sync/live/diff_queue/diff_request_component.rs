use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;
use nimiq_network_interface::network::Network;
use nimiq_primitives::{trie::trie_diff::TrieDiff, TreeProof};
use nimiq_time::sleep;
use parking_lot::RwLock;
use tokio::sync::Semaphore;

use super::{RequestTrieDiff, ResponseTrieDiff};
use crate::sync::{
    live::block_queue::BlockAndSource,
    peer_list::{PeerList, PeerListIndex},
};

pub struct DiffRequestComponent<N: Network> {
    network: Arc<N>,
    peers: Arc<RwLock<PeerList<N>>>,
    current_peer_index: PeerListIndex,
    concurrent_requests: Arc<Semaphore>,
}

impl<N: Network> DiffRequestComponent<N> {
    const NUM_PENDING_DIFFS: usize = 5;

    pub fn new(network: Arc<N>, peers: Arc<RwLock<PeerList<N>>>) -> Self {
        DiffRequestComponent {
            network,
            peers,
            current_peer_index: PeerListIndex::default(),
            concurrent_requests: Arc::new(Semaphore::new(Self::NUM_PENDING_DIFFS)),
        }
    }

    pub fn request_diff(
        &mut self,
    ) -> impl FnMut(&BlockAndSource<N>) -> BoxFuture<'static, Result<TrieDiff, ()>> {
        let mut starting_peer_index = self.current_peer_index.clone();
        self.current_peer_index.increment();

        let peers = Arc::clone(&self.peers);
        let network = Arc::clone(&self.network);
        let concurrent_requests = Arc::clone(&self.concurrent_requests);

        move |(block, block_source)| {
            let peers = Arc::clone(&peers);

            // If we know the peer that sent us this block, we ask them first.
            let mut current_peer_index = peers
                .read()
                .index_of(&block_source.peer_id())
                .unwrap_or_else(|| {
                    starting_peer_index.increment();
                    starting_peer_index.clone()
                });

            let network = Arc::clone(&network);
            let concurrent_requests = Arc::clone(&concurrent_requests);
            let block_desc = format!("{}", block);
            let block_hash = block.hash();
            let block_diff_root = block.diff_root().clone();
            let max_backoff = Duration::from_secs(30);

            Box::pin(async move {
                let _request_permit = concurrent_requests.acquire().await.unwrap();
                let mut num_tries = 0;
                let mut backoff_delay = Duration::from_secs(1);

                loop {
                    let peer_id = peers.read().get(&current_peer_index);
                    let peer_id = match peer_id {
                        Some(peer_id) => peer_id,
                        None => {
                            error!("couldn't fetch diff: no peers");
                            sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    };
                    current_peer_index.increment();

                    let result = network
                        .request(
                            RequestTrieDiff {
                                block_hash: block_hash.clone(),
                            },
                            peer_id,
                        )
                        .await;

                    num_tries += 1;
                    let max_tries = peers.read().len();

                    match result {
                        Ok(ResponseTrieDiff::PartialDiff(diff)) => {
                            if TreeProof::new(diff.0.iter()).root_hash() == block_diff_root {
                                return Ok(diff);
                            }
                            warn!(%peer_id, block = %block_desc, %num_tries, %max_tries, "couldn't fetch diff: invalid diff");
                        }
                        // TODO: remove peer, retry elsewhere
                        Ok(ResponseTrieDiff::IncompleteState) => {
                            debug!(%peer_id, block = %block_desc, %num_tries, %max_tries, "couldn't fetch diff: incomplete state")
                        }
                        Ok(ResponseTrieDiff::UnknownBlockHash) => {
                            debug!(%peer_id, block = %block_desc, %num_tries, %max_tries, "couldn't fetch diff: unknown block hash")
                        }
                        Err(error) => {
                            debug!(%peer_id, block = %block_desc, %num_tries, %max_tries, ?error, "couldn't fetch diff: {}", error)
                        }
                    }

                    if num_tries >= max_tries {
                        error!(%num_tries, %max_tries, ?backoff_delay, "couldn't fetch diff: maximum tries reached");

                        sleep(backoff_delay).await;
                        backoff_delay = Duration::min(backoff_delay * 2, max_backoff);
                        num_tries = 0;
                    }
                }
            })
        }
    }

    pub fn peer_list(&self) -> Arc<RwLock<PeerList<N>>> {
        Arc::clone(&self.peers)
    }
}
