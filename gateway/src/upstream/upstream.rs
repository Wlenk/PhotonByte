use crate::core::pipeline::{Middleware, NextMiddleware};
use crate::middlewares::cache::{Cache, SpeedMode};
use crate::protocols::dns::DnsContext;
use crate::utils::net_probe::measure_ip_port;
use async_trait::async_trait;
use futures::future::join_all;
use hickory_proto::op::Message;
use hickory_proto::op::MessageType;
use hickory_proto::rr::{RData, Record};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{info};

use crate::config::UpstreamConfig;
use reqwest::Client;

fn extract_first_ip(msg: &Message) -> Option<IpAddr> {
    for ans in msg.answers() {
        if let Some(data) = ans.data() {
            match data {
                RData::A(ip) => return Some(IpAddr::V4((*ip).into())),
                RData::AAAA(ip) => return Some(IpAddr::V6((*ip).into())),
                _ => continue,
            }
        }
    }
    None
}

fn is_bogon(ip: &IpAddr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()
}

async fn send_udp(addr: &str, data: &[u8], timeout_ms: u64) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Bind failed: {}", e))?;
    socket
        .send_to(data, addr)
        .await
        .map_err(|e| format!("Send failed: {}", e))?;
    let mut buf = vec![0u8; 512];
    let (len, _) = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "UDP Timeout".to_string())?
    .map_err(|e| format!("Recv failed: {}", e))?;
    buf.truncate(len);
    Ok(buf)
}
async fn send_tcp(addr: &str, data: &[u8], timeout_ms: u64) -> Result<Vec<u8>, String> {
    let mut stream =
        tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr))
            .await
            .map_err(|_| "TCP Connect Timeout".to_string())?
            .map_err(|e| format!("TCP Connect Refused: {}", e))?;
    let len = data.len() as u16;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(data).await.map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|_| "TCP Failed to read length".to_string())?;
    let mut resp_buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
    stream
        .read_exact(&mut resp_buf)
        .await
        .map_err(|_| "TCP Failed to read payload".to_string())?;
    Ok(resp_buf)
}
async fn send_doh(
    client: &Client,
    url: &str,
    data: &[u8],
    timeout_ms: u64,
) -> Result<Vec<u8>, String> {
    let full_url = if url.starts_with("http") {
        url.to_string()
    } else {
        format!("https://{}/dns-query", url.split(':').next().unwrap_or(url))
    };
    let resp = client
        .post(&full_url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(data.to_vec())
        .timeout(Duration::from_millis(timeout_ms))
        .send()
        .await
        .map_err(|e| format!("DoH Failed: {}", e))?;
    if resp.status().is_success() {
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| format!("DoH Body Read Failed: {}", e))
    } else {
        Err(format!("DoH HTTP Error: {}", resp.status()))
    }
}

#[derive(Clone)]
struct IpMeta {
    record: Record,
    count: usize,
    has_doh: bool,
}

pub struct UpstreamRunner {
    pub upstreams: Vec<UpstreamConfig>,
    pub cache: Arc<Cache>,
    pub http_client: Client,
}

impl UpstreamRunner {
    pub fn new(upstreams: Vec<UpstreamConfig>, cache: Arc<Cache>) -> Self {
        let client = Client::builder()
            .pool_max_idle_per_host(2)
            .tcp_keepalive(Duration::from_secs(60))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_default();
        Self {
            upstreams,
            cache,
            http_client: client,
        }
    }
}

#[async_trait]
impl Middleware for UpstreamRunner {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        next: &NextMiddleware<'_>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if ctx.response.is_some() {
            return next.run(ctx).await;
        }
        let packet_data = match ctx.request.to_vec() {
            Ok(data) => data,
            Err(_) => return next.run(ctx).await,
        };
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(String, String, Vec<u8>)>(self.upstreams.len());

        for upstream in &self.upstreams {
            let tx_c = tx.clone();
            let data_c = packet_data.clone();
            let up_c = upstream.clone();
            let client_c = self.http_client.clone();
            tokio::spawn(async move {
                let result = match up_c.protocol.to_lowercase().as_str() {
                    "udp" => send_udp(&up_c.address, &data_c, up_c.timeout_ms).await,
                    "tcp" => send_tcp(&up_c.address, &data_c, up_c.timeout_ms).await,
                    "doh" => send_doh(&client_c, &up_c.address, &data_c, up_c.timeout_ms).await,
                    _ => Err("Unsupported".to_string()),
                };
                if let Ok(resp) = result {
                    let _ = tx_c.send((up_c.name, up_c.protocol, resp)).await;
                }
            });
        }

        let mut final_winner_data = None;
        let mut final_winner_name = String::new();
        let mut all_responses = Vec::new();

        while let Some((name, proto, data)) = rx.recv().await {
            all_responses.push((name.clone(), proto.clone(), data.clone()));

            if final_winner_data.is_none() {
                if let Ok(msg) = Message::from_vec(&data) {
                    if let Some(ip) = extract_first_ip(&msg) {
                        if is_bogon(&ip) {
                            info!("Drop {} from {}", ip, name);
                            continue;
                        }
                        let m443 = measure_ip_port(ip, 443, 1, 0, Duration::from_millis(200)).await;
                        if m443.successes == 0 {
                            let m80 =
                                measure_ip_port(ip, 80, 1, 0, Duration::from_millis(200)).await;
                            if m80.successes == 0 {
                                info!("{} unreachable, waiting...", ip);
                                continue;
                            }
                        }
                    }
                }
                final_winner_data = Some(data);
                final_winner_name = name;
                break;
            }
        }

        if let Some(winner_data) = final_winner_data {
            ctx.skip_cache = true;

            if let Ok(mut msg) = Message::from_vec(&winner_data) {
                for ans in msg.answers_mut() {
                    ans.set_ttl(60);
                }
                ctx.response = Some(msg.to_vec().unwrap_or(winner_data));

                let cache_key = ctx.cache_key();
                let domain = ctx.domain.clone();
                let cache_clone = Arc::clone(&self.cache);
                let expected_total = self.upstreams.len();

                if cache_clone.try_mark_pending(&cache_key) {
                    tokio::spawn(async move {
                        background_aggregate_and_cache(
                            domain,
                            cache_key,
                            msg,
                            rx,
                            all_responses,
                            expected_total,
                            cache_clone,
                        )
                        .await;
                    });
                }
            } else {
                ctx.response = Some(winner_data);
            }
            info!("winner {}", final_winner_name);
        }

        next.run(ctx).await
    }
}
async fn background_aggregate_and_cache(
    domain: String,
    cache_key: String,
    template_msg: Message,
    mut rx: tokio::sync::mpsc::Receiver<(String, String, Vec<u8>)>,
    mut all_responses: Vec<(String, String, Vec<u8>)>,
    expected_total: usize,
    cache: Arc<Cache>,
) {
    let _ = tokio::time::timeout(Duration::from_millis(2000), async {
        while let Some(res) = rx.recv().await {
            all_responses.push(res);
            if all_responses.len() == expected_total {
                break;
            }
        }
    })
    .await;

    let mut ip_pool: HashMap<IpAddr, IpMeta> = HashMap::new();
    let mut other_records: Vec<Record> = Vec::new();

    for (_name, proto, data) in &all_responses {
        if let Ok(msg) = Message::from_vec(data) {
            let is_doh = proto.to_lowercase() == "doh";
            for ans in msg.answers() {
                if let Some(rdata) = ans.data() {
                    let ip_opt = match rdata {
                        RData::A(ip) => Some(IpAddr::V4((*ip).into())),
                        RData::AAAA(ip) => Some(IpAddr::V6((*ip).into())),
                        _ => None,
                    };
                    if let Some(ip) = ip_opt {
                        let meta = ip_pool.entry(ip).or_insert(IpMeta {
                            record: ans.clone(),
                            count: 0,
                            has_doh: false,
                        });
                        meta.count += 1;
                        if is_doh {
                            meta.has_doh = true;
                        }
                    } else {
                        other_records.push(ans.clone());
                    }
                }
            }
        }
    }

    if ip_pool.is_empty() {
        return;
    }

    let all_bogons = ip_pool.keys().all(is_bogon);
    if all_bogons {
        info!("{} returned ONLY bogons. Skipping tests.", domain);
        write_to_cache(
            domain,
            cache_key,
            template_msg,
            ip_pool.values().map(|m| m.record.clone()).collect(),
            other_records,
            cache,
        );
        return;
    }

    let attempts = 4usize;
    let retries = 2usize;
    let timeout_dur = Duration::from_millis(500);
    let mut tasks = Vec::new();

    for (ip, meta) in ip_pool.into_iter() {
        if is_bogon(&ip) {
            continue;
        }
        tasks.push(async move {
            let m443 = measure_ip_port(ip, 443, attempts, retries, timeout_dur).await;
            let m80 = measure_ip_port(ip, 80, attempts, retries, timeout_dur).await;
            (ip, meta, m443, m80)
        });
    }

    let results = join_all(tasks).await;
    let mut candidates: Vec<(Record, f64, f64)> = Vec::new();
    let mut min_latency = f64::MAX;

    let current_mode = cache.get_mode();

    for (ip, meta, m443, m80) in results {
        let actual_latency = if m443.successes > 0 {
            m443.mean_ms()
        } else if m80.successes > 0 {
            m80.mean_ms()
        } else {
            continue;
        };

        if actual_latency < min_latency {
            min_latency = actual_latency;
        }

        let (freq_bonus, doh_bonus) = match current_mode {
            SpeedMode::Aggressive => (
                (meta.count as f64 - 1.0) * 20.0,
                if meta.has_doh { 80.0 } else { 0.0 },
            ),
            SpeedMode::Balanced => (
                (meta.count as f64).ln() * 15.0,
                if meta.has_doh { 50.0 } else { 0.0 },
            ),
            SpeedMode::Conservative => (
                (meta.count as f64).ln() * 10.0,
                if meta.has_doh { 30.0 } else { 0.0 },
            ),
        };

        let final_score = actual_latency - freq_bonus - doh_bonus;

        /*info!(
            "{} | {:.1}ms | Score: {:.1} | DoH: {}",
            ip, actual_latency, final_score, meta.has_doh
        );*/
        candidates.push((meta.record, actual_latency, final_score));
    }

    let mut final_records: Vec<Record> = Vec::new();

    if !candidates.is_empty() {
        let cutoff_limit = match current_mode {
            SpeedMode::Aggressive => 40.0,
            SpeedMode::Balanced => 40.0_f64.max(min_latency * 0.4),
            SpeedMode::Conservative => 50.0_f64.max(min_latency * 0.5),
        };

        candidates.retain(|&(_, latency, _)| latency - min_latency <= cutoff_limit);

        candidates.sort_by(|a, b| a.2.partial_cmp(&b.2).unwrap());
        candidates.truncate(4);

        if cutoff_limit != 40.0 {
            candidates.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        }

        for (mut record, _actual_latency, _score) in candidates {
            record.set_ttl(std::cmp::min(record.ttl(), 600));
            final_records.push(record);
        }
    } else {
        info!("All unreachable. {}", domain);
        return;
    }

    write_to_cache(
        domain,
        cache_key,
        template_msg,
        final_records,
        other_records,
        cache,
    );
}

fn write_to_cache(
    domain: String,
    cache_key: String,
    template: Message,
    ip_records: Vec<Record>,
    other_records: Vec<Record>,
    cache: Arc<Cache>,
) {
    let mut final_records = ip_records;
    for mut record in other_records {
        record.set_ttl(std::cmp::min(record.ttl(), 600));
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
    cache_msg.set_id(template.id());
    cache_msg.set_message_type(MessageType::Response);
    for q in template.queries() {
        cache_msg.add_query(q.clone());
    }
    for record in &deduped {
        cache_msg.add_answer(record.clone());
    }

    if let Ok(bytes) = cache_msg.to_vec() {
        cache.set(cache_key, bytes, 600);
        info!(
            "Cached {} for {} | Mode: {}",
            cache_msg.answers().len(),
            domain,
            cache.get_mode().as_str()
        );
    }
}
