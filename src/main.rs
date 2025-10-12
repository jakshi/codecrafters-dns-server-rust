#[allow(unused_imports)]
use std::net::UdpSocket;

mod dns_header;
use dns_header::{DnsFlags, DnsHeader};

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let request_header = DnsHeader::from_bytes(&buf[0..12]).unwrap_or_else(|e| {
                    eprintln!("Error: {}", e);
                    // Return a default header or handle error differently
                    std::process::exit(1);
                });

                let request_flags = dns_header::DnsFlags::from_u16(request_header.flags);

                // Create response flags in a convenient manner
                let response_flags = DnsFlags {
                    qr: true,                                             // This is a response
                    opcode: request_flags.opcode,                         // Standard query
                    aa: false,                                            // Not authoritative
                    tc: false,                                            // Not truncated
                    rd: request_flags.rd,                                 // Recursion not desired
                    ra: false,                                            // Recursion not available
                    z: 0,                                                 // Reserved
                    rcode: if request_flags.opcode == 0 { 0 } else { 4 }, //     0 (no error) if standard query, else 4 (not implemented
                };

                // Create response header using DnsHeader struct
                let response_header_struct = DnsHeader {
                    id: request_header.id,                         // Echo the request ID
                    flags: response_flags.to_u16(),                // Convert flags to u16
                    question_count: request_header.question_count, // Echo question count
                    answer_count: 1,                               // One answer
                    authority_count: 0,
                    additional_count: 0,
                };

                let response_header = response_header_struct.to_bytes();
                // DNS Question Section (dummy values)
                // Format: QNAME + QTYPE (2 bytes) + QCLASS (2 bytes)
                // Using a simple example: "\x0ccodecrafters\x02io\x00" (codecrafters.io) + TYPE A + CLASS IN
                let response_question: Vec<u8> = vec![
                    // QNAME: codecrafters.io encoded as length-prefixed labels
                    0x0c, b'c', b'o', b'd', b'e', b'c', b'r', b'a', b'f', b't', b'e', b'r',
                    b's', // "codecrafters" (11 chars)
                    0x02, b'i', b'o', // "io" (2 chars)
                    0x00, // null terminator
                    0x00, 0x01, // QTYPE: A record (0x0001)
                    0x00, 0x01, // QCLASS: IN (Internet) (0x0001)
                ];

                let response_answer: Vec<u8> = vec![
                    // NAME: codecrafters.io encoded as length-prefixed labels
                    0x0c, b'c', b'o', b'd', b'e', b'c', b'r', b'a', b'f', b't', b'e', b'r',
                    b's', // "codecrafters" (11 chars)
                    0x02, b'i', b'o', // "io" (2 chars)
                    0x00, // null terminator
                    0x00, 0x01, // TYPE: A record (0x0001)
                    0x00, 0x01, // CLASS: IN (Internet) (0x0001)
                    0x00, 0x00, 0x00, 0x3c, // TTL: 60 seconds
                    0x00, 0x04, // RDLENGTH: 4 bytes
                    0x08, 0x08, 0x08, 0x08, // RDATA: Any IP address (from example 8.8.8.8)
                ];

                // Combine header and question into response
                let mut response = Vec::new();
                response.extend_from_slice(&response_header);
                response.extend_from_slice(&response_question);
                response.extend_from_slice(&response_answer);

                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
