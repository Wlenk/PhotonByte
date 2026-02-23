use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone, Debug)]
pub struct Metrics {
    pub port: u16,
    pub successes: usize,
    pub attempts: usize,
    pub latencies: Vec<Duration>,
}

impl Metrics {
    pub fn packet_loss(&self) -> f64 {
        if self.attempts == 0 { 1.0 }
        else { (self.attempts - self.successes) as f64 / self.attempts as f64 }
    }

    pub fn mean_ms(&self) -> f64 {
        if self.latencies.is_empty() { f64::INFINITY }
        else {
            let sum: f64 = self.latencies.iter().map(|d| d.as_secs_f64() * 1000.0).sum();
            sum / self.latencies.len() as f64
        }
    }

    pub fn variance_ms(&self) -> f64 {
        if self.latencies.len() <= 1 { 0.0 }
        else {
            let mean = self.mean_ms();
            let var: f64 = self.latencies.iter().map(|d| {
                let x = d.as_secs_f64() * 1000.0;
                let diff = x - mean;
                diff * diff
            }).sum();
            var / self.latencies.len() as f64
        }
    }
}

pub async fn measure_ip_port(
    ip: IpAddr,
    port: u16,
    attempts: usize,
    retries: usize,
    timeout_dur: Duration,
) -> Metrics {
    let mut total = 0usize;
    let mut ok = 0usize;
    let mut latencies = Vec::new();

    for r in 0..=retries {
        for _ in 0..attempts {
            total += 1;
            let addr = SocketAddr::new(ip, port);
            let start = Instant::now();
            let res = timeout(timeout_dur, TcpStream::connect(addr)).await;
            if let Ok(Ok(_)) = res {
                ok += 1;
                latencies.push(start.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        if ok == total || r == retries {
            break;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    Metrics {
        port,
        successes: ok,
        attempts: total,
        latencies,
    }
}

pub fn pick_best<T: Clone>(
    candidates: Vec<(T, Metrics)>
) -> Option<(T, Metrics)> {
    let mut c = candidates;
    if c.is_empty() { return None; }

    c.sort_by(|a, b| {
        let la = a.1.packet_loss().partial_cmp(&b.1.packet_loss()).unwrap();
        if la != std::cmp::Ordering::Equal { return la; }

        let va = a.1.variance_ms().partial_cmp(&b.1.variance_ms()).unwrap();
        if va != std::cmp::Ordering::Equal { return va; }

        a.1.mean_ms().partial_cmp(&b.1.mean_ms()).unwrap()
    });

    c.into_iter().next()
}