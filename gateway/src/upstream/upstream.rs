use crate::core::pipeline::{Middleware, NextMiddleware};
use crate::protocols::dns::DnsContext;
use crate::middlewares::cache::Cache;
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

                let cache_key = ctx.cache_key();
                let domain = ctx.domain.clone();
                let cache_clone = Arc::clone(&self.cache);

                if cache_clone.try_mark_pending(&cache_key) {
                    tokio::spawn(async move {
                        tcping_and_cache(cache_key, msg, cache_clone).await;
                    });
                } else {
                    info!("Already probing {}, skip duplicate tcping", domain);
                }
            } else {
                ctx.response = Some(winner_data);
            }
            
            info!("🏁 Upstream winner: {} ({})", winner_name, winner_addr);
        }

        next.run(ctx).await
    }
}

async fn tcping_and_cache(domain: String, msg: Message, cache: Arc<Cache>) {
    
    let mut ip_records: Vec<(IpAddr, Record)> = Vec::new();
    let mut other_records: Vec<Record> = Vec::new();

    for ans in msg.answers() {
        if let Some(data) = ans.data() {
            let ip = match data {
                RData::A(ip) => Some(IpAddr::V4((*ip).into())),
                RData::AAAA(ip) => Some(IpAddr::V6((*ip).into())),
                _ => None,
            };
            if let Some(ip) = ip {
                ip_records.push((ip, ans.clone()));
            } else {
                other_records.push(ans.clone());
            }
        }
    }

    if ip_records.is_empty() { return; }

    let upstream_ip_count = ip_records.len();
    let attempts = 4usize;
    let retries = 2usize;
    let timeout_dur = Duration::from_millis(500);

    let tasks: Vec<_> = ip_records.into_iter().map(|(ip, record)| async move {
        let m443 = measure_ip_port(ip, 443, attempts, retries, timeout_dur).await;
        let m80  = measure_ip_port(ip, 80,  attempts, retries, timeout_dur).await;
        (ip, record, m443, m80)
    }).collect();

    let results = join_all(tasks).await;

    let mut candidates: Vec<(Record, f64)> = Vec::new();
    let mut unreachable_records: Vec<Record> = Vec::new();

    for (_ip, record, m443, m80) in results {
        if m443.successes > 0 {
            candidates.push((record, m443.mean_ms()));
        } else if m80.successes > 0 {
            candidates.push((record, m80.mean_ms()));
        } else {
            unreachable_records.push(record);
        }
    }

    let mut final_records: Vec<Record> = Vec::new();

    if !candidates.is_empty() {
        candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        for (record, latency) in &candidates {
            info!("  candidate: {:?} latency={:.2}ms", record.data(), latency);
        }

        let mut last_latency = candidates[0].1;
        for (mut record, latency) in candidates {
            if final_records.len() >= upstream_ip_count { break; }
            if latency - last_latency > 40.0 && !final_records.is_empty() { break; }
            let ttl_capped = std::cmp::min(record.ttl(), 600);
            record.set_ttl(ttl_capped);
            final_records.push(record);
            last_latency = latency;
        }
    }

    if final_records.is_empty() {
        for mut record in unreachable_records {
            let ttl_capped = std::cmp::min(record.ttl(), 600);
            record.set_ttl(ttl_capped);
            final_records.push(record);
        }
    }

    for mut record in other_records {
        let ttl_capped = std::cmp::min(record.ttl(), 600);
        record.set_ttl(ttl_capped);
        final_records.push(record);
    }

    let mut seen = std::collections::HashSet::new();
    let mut deduped: Vec<Record> = Vec::new();
    for record in final_records {
        let key = format!("{:?}", record.data());
        if seen.insert(key) {
            deduped.push(record);
        }
    }

    let mut cache_msg = Message::new();
    cache_msg.set_id(msg.id());
    cache_msg.set_message_type(MessageType::Response);
    for q in msg.queries().to_vec() {
        cache_msg.add_query(q);
    }
    for record in &deduped {
        cache_msg.add_answer(record.clone());
    }

    if let Ok(bytes) = cache_msg.to_vec() {
        cache.set(domain.clone(), bytes, 600);
        info!("Cached {} IPs for {}", cache_msg.answers().len(), domain);
    }
}