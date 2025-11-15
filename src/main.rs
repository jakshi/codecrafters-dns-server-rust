#[allow(unused_imports)]
use std::net::UdpSocket;

mod dns_header;
mod dns_question_and_answer;

use dns_header::{DnsFlags, DnsHeader};
use dns_question_and_answer::{DnsAnswer, DnsQuestion, RecordClass, RecordType};

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

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

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

                // Create response components
                let answers = create_response_answers(&questions);
                let response_header = create_response_header(&request_header, answers.len() as u16);

                // Build and send response
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
