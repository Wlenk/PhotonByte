use crate::core::pipeline::{Middleware, NextMiddleware};
use crate::protocols::dns::DnsContext;
use crate::utils::blocker::build_blocked_packet;
use crate::utils::domain_match::domain_in_list;
use async_trait::async_trait;
use tracing::info;

pub struct Blacklist {
    pub domains: Vec<String>,
    pub block_mode: String,
}

impl Blacklist {
    pub fn new(domains: Vec<String>, block_mode: String) -> Self {
        Self { domains, block_mode }
    }
}

#[async_trait]
impl Middleware for Blacklist {
    async fn handle(&self, ctx: &mut DnsContext, next: &NextMiddleware<'_>) -> Result<(), Box<dyn std::error::Error>> {
        if domain_in_list(&ctx.domain, &self.domains) {
            info!("Block {} method {}", ctx.domain, self.block_mode);
            let blocked_bytes = build_blocked_packet(&ctx.request, &self.block_mode);
            ctx.response = Some(blocked_bytes);
            return Ok(());
        }
        next.run(ctx).await
    }
}