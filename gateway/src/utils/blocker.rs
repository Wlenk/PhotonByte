use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Record, RData, RecordType};
use std::net::Ipv4Addr;
use std::str::FromStr;

pub fn build_blocked_packet(request: &Message, mode: &str) -> Vec<u8> {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.add_queries(request.queries().to_vec());
    response.set_authoritative(true); 

    match mode.to_lowercase().as_str() {
        "nxdomain" => {
            response.set_response_code(ResponseCode::NXDomain);
        }
        "refused" => {
            response.set_response_code(ResponseCode::Refused);
        }
        ip_str => {
            response.set_response_code(ResponseCode::NoError);
            
            let ip = Ipv4Addr::from_str(ip_str).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));
            
            if let Some(query) = request.queries().first() {
                if query.query_type() == RecordType::A {
                    let mut record = Record::with(query.name().clone(), RecordType::A, 10);
                    record.set_data(Some(RData::A(ip.into())));
                    response.add_answer(record);
                }
            }
        }
    }
    response.to_vec().unwrap_or_default()
}