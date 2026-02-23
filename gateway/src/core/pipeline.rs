use async_trait::async_trait;
use crate::protocols::dns::DnsContext;

#[async_trait]
pub trait Middleware: Send + Sync {
    async fn handle(&self, ctx: &mut DnsContext, next: &NextMiddleware<'_>) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct NextMiddleware<'a> {
    pub remaining: &'a [Box<dyn Middleware>],
}

impl<'a> NextMiddleware<'a> {
    pub async fn run(&self, ctx: &mut DnsContext) -> Result<(), Box<dyn std::error::Error>> {
        if let Some((current, next)) = self.remaining.split_first() {
            let next_wrapper = NextMiddleware { remaining: next };
            current.handle(ctx, &next_wrapper).await
        } else {
            Ok(())
        }
    }
}