use dashmap::DashMap;
use std::time::{Instant, Duration};
use crate::core::pipeline::{Middleware, NextMiddleware};
use crate::protocols::dns::DnsContext;
use async_trait::async_trait;
use tracing::{info};
pub struct Cache {
    records: DashMap<String, (Vec<u8>, Instant)>,
}

impl Cache {
    pub fn new() -> Self {
        Self { records: DashMap::new() }
    }

    pub fn set(&self, domain: String, packet: Vec<u8>, ttl_secs: u64) {
        let expire_at = Instant::now() + Duration::from_secs(ttl_secs);
        self.records.insert(domain, (packet, expire_at));
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
        if let Some(mut cached_bytes) = self.get(&ctx.domain) {
            info!("Direct {}", ctx.domain);

            let req_id = ctx.request.id();
            cached_bytes[0] = (req_id >> 8) as u8;
            cached_bytes[1] = (req_id & 0xff) as u8;

            ctx.response = Some(cached_bytes);
            return Ok(());
        }
        
        if ctx.skip_cache { 
        info!("Skip {}",ctx.domain);
        return Ok(()); }

        next.run(ctx).await?;

        if let Some(resp_bytes) = &ctx.response {
            info!("Cache {}", ctx.domain);
            self.set(ctx.domain.clone(), resp_bytes.clone(), 600);
        }
        
        Ok(())
    }
}