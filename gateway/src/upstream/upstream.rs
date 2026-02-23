use crate::core::pipeline::{Middleware, NextMiddleware};
use crate::protocols::dns::DnsContext;
use crate::middlewares::cache::Cache; // 引入你的缓存结构体
use async_trait::async_trait;
use futures::future::join_all;
use tokio::net::{UdpSocket};
use std::net::IpAddr;
use std::time::{Duration};
use std::sync::Arc;
use hickory_proto::op::MessageType;
use hickory_proto::op::Message;
use tracing::{info};
use hickory_proto::rr::{RData, Record};
use crate::utils::net_probe::{measure_ip_port, pick_best};

use crate::config::UpstreamConfig;

pub struct UpstreamRunner {
    pub upstreams: Vec<UpstreamConfig>,
    pub cache: Arc<Cache>,
}

impl UpstreamRunner {
    pub fn new(upstreams: Vec<UpstreamConfig>, cache: Arc<Cache>) -> Self {
        Self { upstreams, cache }
    }
}

#[async_trait]
impl Middleware for UpstreamRunner {
    async fn handle(&self, ctx: &mut DnsContext, next: &NextMiddleware<'_>) -> Result<(), Box<dyn std::error::Error>> {
        if ctx.response.is_some() { return next.run(ctx).await; }

        let packet_data = match ctx.request.to_vec() {
            Ok(data) => data,
            Err(_) => return next.run(ctx).await,
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String, Vec<u8>)>(self.upstreams.len());

        for upstream in &self.upstreams {
            let tx_c = tx.clone();
            let data_c = packet_data.clone();
            let upstream_c = upstream.clone();

            tokio::spawn(async move {
                if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {

                    if socket.send_to(&data_c, &upstream_c.address).await.is_ok() {

                        let mut buf = [0u8; 512];

                        if let Ok(Ok((len, _))) = tokio::time::timeout(
                            Duration::from_millis(upstream_c.timeout_ms),
                            socket.recv_from(&mut buf)
                        ).await {

                            let _ = tx_c.send((
                                upstream_c.name.clone(),
                                upstream_c.address.clone(),
                                buf[..len].to_vec()
                            )).await;
                        }
                    }
                }
            });
        }

        if let Some((winner_name, winner_addr, winner_data)) = rx.recv().await {
            ctx.skip_cache = true;

            if let Ok(mut msg) = Message::from_vec(&winner_data) {
                for ans in msg.answers_mut() {
                    ans.set_ttl(60);
                }
                ctx.response = Some(msg.to_vec().unwrap_or(winner_data));

                let domain = ctx.domain.clone();
                let cache_clone = Arc::clone(&self.cache);
                
                tokio::spawn(async move {
                    tcping_and_cache(domain, msg, cache_clone).await;
                });
            } else {
                ctx.response = Some(winner_data);
            }
            
            info!("🏁 Upstream winner: {} ({})", winner_name, winner_addr);
        }

        next.run(ctx).await
    }
}

async fn tcping_and_cache(domain: String, msg: Message, cache: Arc<Cache>) {

    let mut ips: Vec<(IpAddr, Record)> = Vec::new();

    for ans in msg.answers() {
        if let Some(data) = ans.data() {
            let ip = match data {
                RData::A(ip) => Some(IpAddr::V4((*ip).into())),
                RData::AAAA(ip) => Some(IpAddr::V6((*ip).into())),
                _ => None,
            };
            if let Some(ip) = ip {
                ips.push((ip, ans.clone()));
            }
        }
    }

    if ips.is_empty() {
        return;
    }

    let attempts = 4usize;
    let retries = 2usize;
    let timeout_dur = Duration::from_millis(500);

    let mut tasks = Vec::new();

    for (ip, record) in ips {
        tasks.push(async move {
            let m443 = measure_ip_port(ip, 443, attempts, retries, timeout_dur).await;
            let m80  = measure_ip_port(ip, 80,  attempts, retries, timeout_dur).await;
            (ip, record, m443, m80)
        });
    }

    let results = join_all(tasks).await;

    let mut c443 = Vec::new();
    let mut c80  = Vec::new();

    for (_ip, record, m443, m80) in results {
        if m443.successes > 0 {
            c443.push((record.clone(), m443));
        }
        if m80.successes > 0 {
            c80.push((record.clone(), m80));
        }
    }

    let chosen = if let Some(best) = pick_best(c443) {
        Some(best)
    } else {
        pick_best(c80)
    };

    if let Some((mut record, metrics)) = chosen {

        let mut cache_msg = Message::new();
        cache_msg.set_id(msg.id());
        cache_msg.set_message_type(MessageType::Response);

        for q in msg.queries().to_vec() {
            cache_msg.add_query(q);
        }

        record.set_ttl(3600);
        cache_msg.add_answer(record);

        if let Ok(bytes) = cache_msg.to_vec() {
            cache.set(domain.clone(), bytes, 3600);
            info!(
                "BEST {} mean={:.2}ms var={:.2} loss={:.3}",
                domain,
                metrics.mean_ms(),
                metrics.variance_ms(),
                metrics.packet_loss()
            );
        }
    }
}