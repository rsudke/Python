use hashlink::LruCache;
use nimiq_bls::LazyPublicKey as BlsLazyPublicKey;
use nimiq_primitives::policy::Policy;

/// LRU cache for BLS remembering uncompression of BLS compressed public key.
pub struct BlsCache {
    inner: LruCache<BlsLazyPublicKey, ()>,
}

impl Default for BlsCache {
    fn default() -> BlsCache {
        BlsCache::with_capacity(Policy::BLS_CACHE_MAX_CAPACITY)
    }
}

impl BlsCache {
    fn with_capacity(capacity: usize) -> BlsCache {
        BlsCache {
            inner: LruCache::new(capacity),
        }
    }
    pub fn new_test() -> BlsCache {
        BlsCache::with_capacity(100)
    }
}

impl BlsCache {
    pub fn cache(&mut self, data: &BlsLazyPublicKey) {
        self.inner.insert(data.clone(), ());
    }
}
