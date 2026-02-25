use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, error};

use crate::core::{api, pipeline::{Middleware, NextMiddleware}};

mod config;
mod utils;
mod core;
mod middlewares;
mod upstream;
mod protocols;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    tracing_subscriber::fmt::init();
    info!("Starting PhotonByte Gateway (DNS Mode)...");

    let app_config = match config::GatewayConfig::load("config.toml") {
        Ok(cfg) => cfg,
        Err(_) => {
            error!("Config not found");
            std::process::exit(1);
        }
    };

    let listen_addr = &app_config.server.listen_addr;
    

    let dns_cache = std::sync::Arc::new(middlewares::cache::Cache::new(5000));

    let api_cache_clone = std::sync::Arc::clone(&dns_cache);
    
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:5354").await.unwrap();
        let app = api::build_router(api_cache_clone);
        
        tracing::info!("🚀 API Server running on http://0.0.0.0:5354");
        axum::serve(listener, app).await.unwrap();
    });
    info!("loading pipeline");
    let mut pipeline_builder: Vec<Box<dyn core::pipeline::Middleware>> = Vec::new();

    if !app_config.rules.blacklist.is_empty() {
        pipeline_builder.push(Box::new(middlewares::blacklist::Blacklist::new(
            app_config.rules.blacklist.clone(),
            app_config.rules.block_mode.clone(),
        )));
    }

    pipeline_builder.push(Box::new(std::sync::Arc::clone(&dns_cache)));

    let runner = upstream::UpstreamRunner::new(
        app_config.upstreams.clone(),
        Arc::clone(&dns_cache),
    );
    pipeline_builder.push(Box::new(runner));

    let pipeline = std::sync::Arc::new(pipeline_builder);

    info!("Port bounded {}", listen_addr);
    let socket: Arc<UdpSocket> = match UdpSocket::bind(listen_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("bind failed {}", e);
            return Err(e.into());
        }
    };

    info!("Listening DNS packets");
    let mut buf = [0u8; 512];
    loop {
        let (len, peer_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                tracing::error!("Recv failed {}", e);
                continue;
            }
        };

        let packet_data = buf[..len].to_vec();
        let socket_clone = std::sync::Arc::clone(&socket);
        let pipeline_clone = std::sync::Arc::clone(&pipeline);

        tokio::spawn(async move {
            if let Some(msg) = protocols::dns::DnsProcessor::decode(&packet_data) {
                if let Some(domain) = protocols::dns::DnsProcessor::get_question_name(&msg) {
                    
                    let mut ctx = protocols::dns::DnsContext::new(peer_addr, msg, domain.clone());

                    let runner = core::pipeline::NextMiddleware { remaining: &pipeline_clone };
                    if let Err(e) = runner.run(&mut ctx).await {
                        tracing::error!("Failed [{}]: {}", domain, e);
                    }
                    
                    if let Some(resp_bytes) = ctx.response {
                        if let Err(e) = socket_clone.send_to(&resp_bytes, peer_addr).await {
                            tracing::error!("Failed {}", e);
                        }// else {
                            //tracing::info!("Successful {}", domain);
                        //}
                    }
                }
            }
        });
    }
}
