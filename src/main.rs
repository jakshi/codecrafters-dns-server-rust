#[allow(unused_imports)]
use std::net::UdpSocket;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                // DNS Header (12 bytes)
                let header: [u8; 12] = [0x04, 0xd2, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                // DNS Question Section (dummy values)
                // Format: QNAME + QTYPE (2 bytes) + QCLASS (2 bytes)
                // Using a simple example: "\x0ccodecrafters\x02io\x00" (codecrafters.io) + TYPE A + CLASS IN
                let question: Vec<u8> = vec![
                    // QNAME: example.com encoded as length-prefixed labels
                    0x0c, b'c', b'o', b'd', b'e', b'c', b'r', b'a', b'f', b't', b'e', b'r',
                    b's', // "codecrafters" (11 chars)
                    0x02, b'i', b'o', // "io" (2 chars)
                    0x00, // null terminator
                    // QTYPE: A record (0x0001)
                    0x00, 0x01, // QCLASS: IN (Internet) (0x0001)
                    0x00, 0x01,
                ];

                // Combine header and question into response
                let mut response = Vec::new();
                response.extend_from_slice(&header);
                response.extend_from_slice(&question);

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
