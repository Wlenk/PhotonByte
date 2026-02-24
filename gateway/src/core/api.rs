use axum::{
    extract::{Path, State},
    routing::{get, put, delete},
    Router, Json,
};
use tower_http::cors::{Any, CorsLayer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;

use crate::middlewares::cache::{Cache, SpeedMode}; 

pub struct AppState {
    pub cache: Arc<Cache>,
}

pub fn build_router(cache: Arc<Cache>) -> Router {
    let state = Arc::new(AppState { cache });

    // 允许任何来源、任何方法的跨域请求 (方便前端调试)
    let cors: CorsLayer = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    Router::new()
        .route("/cache/list", get(list_cache))
        .route("/cache/detail/:key", get(get_detail))
        .route("/cache/one/:key", delete(delete_one))
        .route("/cache/all", delete(clear_all))
        .route("/stats", get(get_stats))
        .route("/config/mode", get(get_mode).put(set_mode))
        .with_state(state).layer(cors)
}

async fn list_cache(State(state): State<Arc<AppState>>) -> Json<Value> {
    let keys = state.cache.get_all_keys();
    Json(json!({ "status": "success", "total": keys.len(), "keys": keys }))
}

async fn get_detail(
    Path(key): Path<String>,
    State(state): State<Arc<AppState>>
) -> Json<Value> {
    if let Some(packet) = state.cache.get_raw(&key) {
        if let Ok(msg) = Message::from_vec(&packet) {
            let ips: Vec<String> = msg.answers().iter().filter_map(|ans| {
                if let Some(rdata) = ans.data() {
                    match rdata {
                        RData::A(ip) => Some(ip.to_string()),
                        RData::AAAA(ip) => Some(ip.to_string()),
                        RData::CNAME(name) => Some(format!("CNAME: {}", name)),
                        _ => Some("Other Record".to_string()),
                    }
                } else {
                    None
                }
            }).collect();
            return Json(json!({ "status": "success", "key": key, "ips": ips }));
        }
    }
    Json(json!({ "status": "not_found", "message": format!("No cache found for {}", key) }))
}

async fn delete_one(
    Path(key): Path<String>,
    State(state): State<Arc<AppState>>
) -> Json<Value> {
    let success = state.cache.remove_record(&key);
    if success {
        Json(json!({ "status": "success", "message": format!("Deleted cache for {}", key) }))
    } else {
        Json(json!({ "status": "not_found", "message": format!("No cache found for {}", key) }))
    }
}

async fn clear_all(State(state): State<Arc<AppState>>) -> Json<Value> {
    state.cache.clear_all();
    Json(json!({ "status": "success", "message": "All DNS caches cleared" }))
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Json<Value> {
    let (current, max) = state.cache.get_stats();
    let mode = state.cache.get_mode().as_str();
    Json(json!({ 
        "status": "success", 
        "mode": mode,
        "cache_usage": current, 
        "max_capacity": max 
    }))
}

async fn get_mode(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mode = state.cache.get_mode().as_str();
    Json(json!({ "status": "success", "mode": mode }))
}

#[derive(Deserialize)]
struct ModePayload {
    mode: String,
}

async fn set_mode(
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<ModePayload>
) -> Json<Value> {
    let new_mode = match payload.mode.to_lowercase().as_str() {
        "aggressive" => SpeedMode::Aggressive,
        "balanced" => SpeedMode::Balanced,
        "conservative" => SpeedMode::Conservative,
        _ => return Json(json!({ 
            "status": "error", 
            "message": "Invalid mode. Use 'aggressive', 'balanced', or 'conservative'." 
        })),
    };

    state.cache.set_mode(new_mode);
    Json(json!({ "status": "success", "message": format!("Mode successfully changed to {}", new_mode.as_str()) }))
}