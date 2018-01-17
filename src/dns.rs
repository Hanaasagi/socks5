extern crate trust_dns;
extern crate futures;
extern crate tokio_core;

use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;

use futures::Future;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::client::{BasicClientHandle, ClientHandle};
use trust_dns::op::ResponseCode;

#[derive(Clone)]
pub struct DNSClient {
    client: BasicClientHandle,
}

impl DNSClient {
    pub fn new(client: BasicClientHandle) -> DNSClient {

        DNSClient {
            client: client
        }
    }

    pub fn lookup(&mut self, name: Name, port: u16)
                    -> Box<Future<Item=SocketAddr, Error=io::Error>>{
        let ipv4 = self.client.query(name, DNSClass::IN, RecordType::A)
            .map_err(|e| other(&format!("dns error: {}", e)))
            .and_then(move |response| {
                // Extracts the first IP address from the response.
                if response.get_response_code() != ResponseCode::NoError {
                    return Err(other("resolution failed"));
                }
                let addr = response.get_answers().iter().filter_map(|ans| {
                    match *ans.get_rdata() {
                        RData::A(addr) => Some(IpAddr::V4(addr)),
                        RData::AAAA(addr) => Some(IpAddr::V6(addr)),
                        _ => None,
                    }
                }).next();

                match addr {
                    Some(addr) => Ok(SocketAddr::new(addr, port)),
                    None => Err(other("no address records in response")),
                }
            });
        return Box::new(ipv4);
    }
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}
