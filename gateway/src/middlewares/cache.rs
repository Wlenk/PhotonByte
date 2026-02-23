use dashmap::DashMap;
use dashmap::DashSet;
use std::time::{Instant, Duration};
use crate::core::pipeline::{Middleware, NextMiddleware};
use crate::protocols::dns::DnsContext;
use async_trait::async_trait;
use tracing::info;

pub struct Cache {
    records: DashMap<String, (Vec<u8>, Instant)>,
    pending: DashSet<String>, // 正在测速中的域名
}

impl Cache {
    pub fn new() -> Self {
        Self {
            records: DashMap::new(),
            pending: DashSet::new(),
        }
    }

    pub fn set(&self, domain: String, packet: Vec<u8>, ttl_secs: u64) {
        let expire_at = Instant::now() + Duration::from_secs(ttl_secs);
        self.records.insert(domain.clone(), (packet, expire_at));
        self.pending.remove(&domain); // 测速完成，移除pending标记
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

    /// 尝试标记为pending，返回false说明已经有其他请求在测速了
    pub fn try_mark_pending(&self, domain: &String) -> bool {
        self.pending.insert(domain.clone())
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
            info!("Skip cache write for {} (upstream handled)", ctx.domain);
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