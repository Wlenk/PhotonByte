use dashmap::DashMap;
use dashmap::DashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Instant, Duration};
use crate::core::pipeline::{Middleware, NextMiddleware};
use crate::protocols::dns::DnsContext;
use async_trait::async_trait;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeedMode {
    Aggressive,
    Balanced,
    Conservative,
}

impl SpeedMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpeedMode::Aggressive => "Aggressive",
            SpeedMode::Balanced => "Balanced",
            SpeedMode::Conservative => "Conservative",
        }
    }
}

#[derive(Clone)]
pub struct Cache {
    records: Arc<DashMap<String, (Vec<u8>, Instant)>>,
    pending: Arc<DashSet<String>>,
    max_capacity: usize,
    mode: Arc<RwLock<SpeedMode>>, 
}

impl Cache {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            pending: Arc::new(DashSet::new()),
            max_capacity,
            mode: Arc::new(RwLock::new(SpeedMode::Aggressive)), 
        }
    }

    pub fn get_mode(&self) -> SpeedMode {
        *self.mode.read().unwrap()
    }

    pub fn set_mode(&self, new_mode: SpeedMode) {
        if let Ok(mut m) = self.mode.write() {
            *m = new_mode;
        }
    }

    pub fn set(&self, domain: String, packet: Vec<u8>, ttl_secs: u64) {
        if self.records.len() >= self.max_capacity {
            self.evict_expired(); 
            
            if self.records.len() >= self.max_capacity {
                self.evict_random(self.max_capacity / 10);
            }
        }

        let expire_at = Instant::now() + Duration::from_secs(ttl_secs);
        self.records.insert(domain.clone(), (packet, expire_at));
        self.pending.remove(&domain); 
    }

    pub fn get(&self, domain: &String) -> Option<Vec<u8>> {
        if let Some(entry) = self.records.get(domain) {
            let (packet, expire_at) = entry.value();
            if Instant::now() < *expire_at {
                return Some(packet.clone());
            } else {
                drop(entry);
                self.records.remove(domain);
            }
        }
        None
    }

    pub fn try_mark_pending(&self, domain: &String) -> bool {
        self.pending.insert(domain.clone())
    }

    pub fn get_all_keys(&self) -> Vec<String> {
        self.records.iter().map(|entry| entry.key().clone()).collect()
    }

    pub fn remove_record(&self, domain: &str) -> bool {
        self.records.remove(domain).is_some()
    }

    pub fn clear_all(&self) {
        self.records.clear();
        self.pending.clear();
    }

    pub fn get_stats(&self) -> (usize, usize) {
        (self.records.len(), self.max_capacity)
    }

    pub fn get_raw(&self, domain: &str) -> Option<Vec<u8>> {
        self.records.get(domain).map(|entry| entry.value().0.clone())
    }

    fn evict_expired(&self) {
        let now = Instant::now();
        self.records.retain(|_, (_, expire_at)| *expire_at > now);
    }

    fn evict_random(&self, count: usize) {
        let mut to_remove = Vec::with_capacity(count);
        for entry in self.records.iter().take(count) {
            to_remove.push(entry.key().clone());
        }
        for k in to_remove {
            self.records.remove(&k);
        }
    }
}

#[async_trait]
impl<T: Middleware + Send + Sync + ?Sized> Middleware for std::sync::Arc<T> {
    async fn handle(&self, ctx: &mut DnsContext, next: &NextMiddleware<'_>) -> Result<(), Box<dyn std::error::Error>> {
        (**self).handle(ctx, next).await
    }
}

#[async_trait]
impl Middleware for Cache {
    async fn handle(&self, ctx: &mut DnsContext, next: &NextMiddleware<'_>) -> Result<(), Box<dyn std::error::Error>> {
        let key = ctx.cache_key();

        if let Some(mut cached_bytes) = self.get(&key) {
            info!("Direct {}", ctx.domain);
            let req_id = ctx.request.id();
            cached_bytes[0] = (req_id >> 8) as u8;
            cached_bytes[1] = (req_id & 0xff) as u8;
            ctx.response = Some(cached_bytes);
            return Ok(());
        }

        next.run(ctx).await?;

        if ctx.skip_cache {
            return Ok(());
        }

        if let Some(resp_bytes) = &ctx.response {
            info!("Cache {}", ctx.domain);
            let cache_ttl: u64 = if let Ok(msg) = hickory_proto::op::Message::from_vec(resp_bytes) {
                let min_ttl = msg.answers().iter().map(|a| a.ttl()).min().unwrap_or(60);
                std::cmp::min(min_ttl as u64, 600)
            } else {
                600
            };
            self.set(key, resp_bytes.clone(), cache_ttl);
        }

        Ok(())
    }
}