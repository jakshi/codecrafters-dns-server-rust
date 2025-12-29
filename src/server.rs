use std::net::UdpSocket;

use crate::dns_message::{build_response, create_response_header, parse_request};
use crate::forwarder::forward_to_resolver;
use crate::local::create_response_answers;

/// DNS Server that handles incoming DNS requests
pub struct DnsServer {
    socket: UdpSocket,
    resolver: Option<String>,
}

impl DnsServer {
    /// Create a new DNS server bound to the given address
    /// Optionally configure an upstream resolver for forwarding queries
    pub fn new(bind_addr: &str, resolver: Option<String>) -> Result<Self, String> {
        let socket = UdpSocket::bind(bind_addr)
            .map_err(|e| format!("Failed to bind to {}: {}", bind_addr, e))?;

        Ok(Self { socket, resolver })
    }

    /// Run the DNS server main loop
    /// Listens for incoming requests and sends responses
    pub fn run(&self) {
        let mut buf = [0u8; 512];

        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((size, source)) => {
                    println!("Received {} bytes from {}", size, source);

                    match self.handle_request(&buf[..size]) {
                        Ok(response) => {
                            self.socket
                                .send_to(&response, source)
                                .expect("Failed to send response");
                        }
                        Err(e) => {
                            eprintln!("Error handling request: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error receiving data: {}", e);
                    break;
                }
            }
        }
    }

    /// Handle a DNS request: parse, resolve, and build response
    fn handle_request(&self, buf: &[u8]) -> Result<Vec<u8>, String> {
        // Parse the request
        let (request_header, questions) = parse_request(buf)?;

        // Get answers - either from upstream resolver or generate locally
        let answers = if let Some(resolver_addr) = &self.resolver {
            // Forward the request to the upstream resolver
            forward_to_resolver(resolver_addr, request_header.id, &questions)?
        } else {
            // No resolver configured - create dummy response locally
            create_response_answers(&questions)
        };

        // Build response
        let response_header = create_response_header(&request_header, answers.len() as u16);
        let response = build_response(&response_header, &questions, &answers);

        Ok(response)
    }
}
