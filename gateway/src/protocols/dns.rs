use hickory_proto::op::Message;
use std::net::SocketAddr;
use tracing::{error};

pub struct DnsProcessor;

impl DnsProcessor {
    pub fn decode(bytes: &[u8]) -> Option<Message> {
        match Message::from_vec(bytes) {
            Ok(msg) => Some(msg),
            Err(e) => {
                error!("[Protocol|DNS] Failed to decode {:?}", e);
                None
            }
        }
    }

    pub fn get_question_name(msg: &Message) -> Option<String> {
        msg.queries().first().map(|q| q.name().to_string().to_lowercase())
    }
}


pub struct DnsContext {
    pub client_addr: SocketAddr,
    pub request: Message,
    pub domain: String,
    pub skip_cache: bool,
    pub response: Option<Vec<u8>>,
}

impl DnsContext {
    pub fn cache_key(&self) -> String {
        let qtype = self.request.queries()
            .first()
            .map(|q| q.query_type().to_string())
            .unwrap_or_default();
        format!("{}:{}", self.domain, qtype)
    }
    pub fn new(client_addr: SocketAddr, request: Message, domain: String) -> Self {
        Self {
            client_addr,
            request,
            domain,
            response: None,
            skip_cache: false,
        }
    }
}
