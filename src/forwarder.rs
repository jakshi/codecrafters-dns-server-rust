use std::net::UdpSocket;

use crate::dns_header::DnsHeader;
use crate::dns_question_and_answer::{DnsAnswer, DnsQuestion};

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

/// Build a DNS query with a single question to send to upstream resolver
fn build_single_question_query(original_id: u16, question: &DnsQuestion) -> Vec<u8> {
    let mut query = Vec::new();

    // Build header for a standard query
    let header = DnsHeader {
        id: original_id,
        flags: 0x0100, // Cloudflare 1.1.1.1 would like RD bit to be set (using 0x0100 for RD=1)
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

/// Forward questions to upstream resolver and collect answers
/// Creates a new socket, sends each question individually, and collects all answers
pub fn forward_to_resolver(
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
