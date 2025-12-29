use crate::dns_header::{DnsFlags, DnsHeader};
use crate::dns_question_and_answer::{DnsAnswer, DnsQuestion};

/// Parse the DNS request from the buffer
/// Takes an immutable borrow of the buffer, returns owned structures
pub fn parse_request(buf: &[u8]) -> Result<(DnsHeader, Vec<DnsQuestion>), String> {
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
pub fn create_response_header(request_header: &DnsHeader, answer_count: u16) -> DnsHeader {
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

/// Build the complete DNS response message
pub fn build_response(
    header: &DnsHeader,
    questions: &[DnsQuestion],
    answers: &[DnsAnswer],
) -> Vec<u8> {
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
