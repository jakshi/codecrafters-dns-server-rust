#[allow(unused_imports)]
use std::net::UdpSocket;

mod dns_header;
mod dns_question_and_answer;

use dns_header::{DnsFlags, DnsHeader};
use dns_question_and_answer::{DnsAnswer, DnsQuestion};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "dns-server")]
struct Args {
    /// Upstream DNS resolver address (e.g., 8.8.8.8:53)
    #[arg(long)]
    resolver: Option<String>,
}

/// Parse the DNS request from the buffer
/// Takes an immutable borrow of the buffer, returns owned structures
fn parse_request(buf: &[u8]) -> Result<(DnsHeader, Vec<DnsQuestion>), String> {
    let header =
        DnsHeader::from_bytes(&buf[0..12]).map_err(|e| format!("Failed to parse header: {}", e))?;

    let mut questions = Vec::new();
    let mut offset = 12; // Start after header

    for _ in 0..header.question_count {
        let (question, new_offset) = DnsQuestion::from_bytes(buf, offset)?;
        questions.push(question);
        offset = new_offset;
    }

    Ok((header, questions))
}

/// Parse answers from an upstream DNS response
/// Returns the answers extracted from the response
fn parse_answers_from_response(buf: &[u8]) -> Result<Vec<DnsAnswer>, String> {
    // Parse the header first to get answer count
    let header = DnsHeader::from_bytes(&buf[0..12])
        .map_err(|e| format!("Failed to parse response header: {}", e))?;

    let mut offset = 12; // Start after header

    // Skip over the question section
    for _ in 0..header.question_count {
        let (_, new_offset) = DnsQuestion::from_bytes(buf, offset)?;
        offset = new_offset;
    }

    // Parse the answers
    let mut answers = Vec::new();
    for _ in 0..header.answer_count {
        let (answer, new_offset) = DnsAnswer::from_bytes(buf, offset)?;
        answers.push(answer);
        offset = new_offset;
    }

    Ok(answers)
}

/// Create response header based on request header
/// Takes a reference to request header, returns owned response header
fn create_response_header(request_header: &DnsHeader, answer_count: u16) -> DnsHeader {
    let request_flags = DnsFlags::from_u16(request_header.flags);

    let response_flags = DnsFlags {
        qr: true,                                             // This is a response
        opcode: request_flags.opcode,                         // Echo opcode
        aa: false,                                            // Not authoritative
        tc: false,                                            // Not truncated
        rd: request_flags.rd,                                 // Echo recursion desired
        ra: false,                                            // Recursion not available
        z: 0,                                                 // Reserved
        rcode: if request_flags.opcode == 0 { 0 } else { 4 }, // 0 (no error) if standard query, else 4 (not implemented)
    };

    DnsHeader {
        id: request_header.id,                         // Echo request ID
        flags: response_flags.to_u16(),                // Convert flags to u16
        question_count: request_header.question_count, // Echo question count
        answer_count,                                  // Number of answers we're providing
        authority_count: 0,
        additional_count: 0,
    }
}

/// Create response answers based on the questions
/// Takes a reference to questions, returns owned answer structures
fn create_response_answers(questions: &[DnsQuestion]) -> Vec<DnsAnswer> {
    questions
        .iter()
        .map(|question| {
            // For now, return a dummy A record pointing to 8.8.8.8
            DnsAnswer::new_a_record(
                question.name.clone(),
                60, // TTL: 60 seconds
                [8, 8, 8, 8],
            )
        })
        .collect()
}

/// Build the complete DNS response message
fn build_response(header: &DnsHeader, questions: &[DnsQuestion], answers: &[DnsAnswer]) -> Vec<u8> {
    let mut response = Vec::new();

    // Add header
    response.extend_from_slice(&header.to_bytes());

    // Add questions (echo them back)
    for question in questions {
        response.extend(question.to_bytes());
    }

    // Add answers
    for answer in answers {
        response.extend(answer.to_bytes());
    }

    response
}

/// Forward questions to upstream resolver and collect answers
/// Creates a new socket, sends each question individually, and collects all answers
fn forward_to_resolver(
    resolver_addr: &str,
    request_id: u16,
    questions: &[DnsQuestion],
) -> Result<Vec<DnsAnswer>, String> {
    // Create a socket for upstream communication
    let upstream_socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind upstream socket: {}", e))?;

    let mut answers = Vec::new();

    // Public resolvers often like single question, so we split them
    for question in questions {
        let single_query = build_single_question_query(request_id, question);

        // Forward to resolver
        upstream_socket
            .send_to(&single_query, resolver_addr)
            .map_err(|e| format!("Failed to send to resolver: {}", e))?;

        // Receive response from upstream resolver
        let mut response_buf = [0u8; 512];
        let (response_size, _) = upstream_socket
            .recv_from(&mut response_buf)
            .map_err(|e| format!("Failed to receive from resolver: {}", e))?;

        // Parse answers from upstream response
        let mut parsed_answers = parse_answers_from_response(&response_buf[..response_size])?;
        answers.append(&mut parsed_answers);
    }

    Ok(answers)
}

/// Build a DNS query with a single question to send to upstream resolver
fn build_single_question_query(original_id: u16, question: &DnsQuestion) -> Vec<u8> {
    let mut query = Vec::new();

    // Build header for a standard query
    let header = DnsHeader {
        id: original_id,
        flags: 0x0100, // Claudflare 1.1.1.1 would like RD bit to be set (using 0x0100 for RD=1)
        question_count: 1, // Single question
        answer_count: 0,
        authority_count: 0,
        additional_count: 0,
    };

    // Add header
    query.extend_from_slice(&header.to_bytes());

    // Add the single question
    query.extend(question.to_bytes());

    query
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let args = Args::parse();

    let resolver = args.resolver.as_ref();

    if let Some(addr) = resolver {
        println!("Using resolver: {}", addr);
    }

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                // Parse the request
                let (request_header, questions) = match parse_request(&buf[..size]) {
                    Ok(result) => result,
                    Err(e) => {
                        eprintln!("Error parsing request: {}", e);
                        continue;
                    }
                };

                // Get answers - either from upstream resolver or generate locally
                let answers = if let Some(resolver_addr) = resolver {
                    // Forward the request to the upstream resolver
                    match forward_to_resolver(resolver_addr, request_header.id, &questions) {
                        Ok(ans) => ans,
                        Err(e) => {
                            eprintln!("Error forwarding to resolver: {}", e);
                            continue;
                        }
                    }
                } else {
                    // No resolver configured - create dummy response locally
                    create_response_answers(&questions)
                };

                // Build and send response
                let response_header = create_response_header(&request_header, answers.len() as u16);
                let response = build_response(&response_header, &questions, &answers);

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
