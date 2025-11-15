use std::io::{self, Cursor, Read};

/// DNS Question Section
/// Format: QNAME + QTYPE (2 bytes) + QCLASS (2 bytes)
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String, // Domain name (e.g., "example.com")
    pub qtype: u16,   // Query type (A, AAAA, CNAME, etc.)
    pub qclass: u16,  // Query class (usually IN for Internet)
}

/// DNS Answer/Resource Record Section
/// Format: NAME + TYPE (2 bytes) + CLASS (2 bytes) + TTL (4 bytes) + RDLENGTH (2 bytes) + RDATA
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,   // Domain name
    pub rtype: u16,     // Record type (A, AAAA, CNAME, etc.)
    pub rclass: u16,    // Record class (usually IN for Internet)
    pub ttl: u32,       // Time to live in seconds
    pub rdlength: u16,  // Length of RDATA field
    pub rdata: Vec<u8>, // Resource data (format depends on record type)
}

/// Common DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A = 1,     // IPv4 address
    NS = 2,    // Name server
    CNAME = 5, // Canonical name
    SOA = 6,   // Start of authority
    PTR = 12,  // Pointer record
    MX = 15,   // Mail exchange
    TXT = 16,  // Text record
    AAAA = 28, // IPv6 address
    OPT = 41,  // EDNS0 option
}

impl RecordType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(RecordType::A),
            2 => Some(RecordType::NS),
            5 => Some(RecordType::CNAME),
            6 => Some(RecordType::SOA),
            12 => Some(RecordType::PTR),
            15 => Some(RecordType::MX),
            16 => Some(RecordType::TXT),
            28 => Some(RecordType::AAAA),
            41 => Some(RecordType::OPT),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Common DNS classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    IN = 1, // Internet
    CS = 2, // CSNET (obsolete)
    CH = 3, // CHAOS
    HS = 4, // Hesiod
}

impl RecordClass {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(RecordClass::IN),
            2 => Some(RecordClass::CS),
            3 => Some(RecordClass::CH),
            4 => Some(RecordClass::HS),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }
}

impl DnsQuestion {
    /// Parse a DNS question from bytes starting at the given offset
    /// Returns the question and the new offset after parsing
    pub fn from_bytes(bytes: &[u8], offset: usize) -> Result<(Self, usize), String> {
        let (name, new_offset) = parse_domain_name(bytes, offset)?;

        if new_offset + 4 > bytes.len() {
            return Err("Buffer too small for question type and class".to_string());
        }

        let qtype = u16::from_be_bytes([bytes[new_offset], bytes[new_offset + 1]]);
        let qclass = u16::from_be_bytes([bytes[new_offset + 2], bytes[new_offset + 3]]);

        Ok((
            DnsQuestion {
                name,
                qtype,
                qclass,
            },
            new_offset + 4,
        ))
    }

    /// Convert the question to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode domain name
        bytes.extend(encode_domain_name(&self.name));

        // Add type and class
        bytes.extend(&self.qtype.to_be_bytes());
        bytes.extend(&self.qclass.to_be_bytes());

        bytes
    }
}

impl DnsAnswer {
    /// Parse a DNS answer/resource record from bytes starting at the given offset
    /// Returns the answer and the new offset after parsing
    pub fn from_bytes(bytes: &[u8], offset: usize) -> Result<(Self, usize), String> {
        let (name, new_offset) = parse_domain_name(bytes, offset)?;

        if new_offset + 10 > bytes.len() {
            return Err("Buffer too small for answer fields".to_string());
        }

        let rtype = u16::from_be_bytes([bytes[new_offset], bytes[new_offset + 1]]);
        let rclass = u16::from_be_bytes([bytes[new_offset + 2], bytes[new_offset + 3]]);
        let ttl = u32::from_be_bytes([
            bytes[new_offset + 4],
            bytes[new_offset + 5],
            bytes[new_offset + 6],
            bytes[new_offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([bytes[new_offset + 8], bytes[new_offset + 9]]);

        let data_offset = new_offset + 10;
        if data_offset + rdlength as usize > bytes.len() {
            return Err("Buffer too small for RDATA".to_string());
        }

        let rdata = bytes[data_offset..data_offset + rdlength as usize].to_vec();

        Ok((
            DnsAnswer {
                name,
                rtype,
                rclass,
                ttl,
                rdlength,
                rdata,
            },
            data_offset + rdlength as usize,
        ))
    }

    /// Convert the answer to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Encode domain name
        bytes.extend(encode_domain_name(&self.name));

        // Add type, class, TTL, and data length
        bytes.extend(&self.rtype.to_be_bytes());
        bytes.extend(&self.rclass.to_be_bytes());
        bytes.extend(&self.ttl.to_be_bytes());
        bytes.extend(&self.rdlength.to_be_bytes());

        // Add resource data
        bytes.extend(&self.rdata);

        bytes
    }

    /// Create a new DNS answer with the given parameters
    pub fn new(name: String, rtype: u16, rclass: u16, ttl: u32, rdata: Vec<u8>) -> Self {
        let rdlength = rdata.len() as u16;
        DnsAnswer {
            name,
            rtype,
            rclass,
            ttl,
            rdlength,
            rdata,
        }
    }

    /// Create an A record (IPv4 address) answer
    pub fn new_a_record(name: String, ttl: u32, ip: [u8; 4]) -> Self {
        Self::new(
            name,
            RecordType::A.to_u16(),
            RecordClass::IN.to_u16(),
            ttl,
            ip.to_vec(),
        )
    }

    /// Create an AAAA record (IPv6 address) answer
    pub fn new_aaaa_record(name: String, ttl: u32, ip: [u8; 16]) -> Self {
        Self::new(
            name,
            RecordType::AAAA.to_u16(),
            RecordClass::IN.to_u16(),
            ttl,
            ip.to_vec(),
        )
    }
}

/// Parse a domain name from DNS message format
/// Supports DNS name compression (pointers)
/// Returns the parsed domain name and the new offset
pub fn parse_domain_name(bytes: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_offset = offset;
    let max_jumps = 5; // Prevent infinite loops
    let mut jumps = 0;

    loop {
        if offset >= bytes.len() {
            return Err("Offset out of bounds while parsing domain name".to_string());
        }

        let length = bytes[offset];

        // Check if this is a pointer (compression)
        if (length & 0xC0) == 0xC0 {
            if offset + 1 >= bytes.len() {
                return Err("Incomplete pointer in domain name".to_string());
            }

            // Pointer: the next 14 bits indicate the offset
            let pointer = u16::from_be_bytes([bytes[offset] & 0x3F, bytes[offset + 1]]);

            if !jumped {
                jump_offset = offset + 2;
            }

            offset = pointer as usize;
            jumped = true;
            jumps += 1;

            if jumps > max_jumps {
                return Err("Too many jumps while parsing domain name".to_string());
            }
            continue;
        }

        // Move past the length byte
        offset += 1;

        // Check for end of name
        if length == 0 {
            break;
        }

        // Read the label
        if offset + length as usize > bytes.len() {
            return Err("Label extends beyond buffer".to_string());
        }

        let label = std::str::from_utf8(&bytes[offset..offset + length as usize])
            .map_err(|_| "Invalid UTF-8 in domain label".to_string())?;

        labels.push(label.to_string());
        offset += length as usize;
    }

    let final_offset = if jumped { jump_offset } else { offset };
    let domain_name = if labels.is_empty() {
        ".".to_string() // Root domain
    } else {
        labels.join(".")
    };

    Ok((domain_name, final_offset))
}

/// Encode a domain name to DNS message format
/// Format: length-prefixed labels terminated with a null byte
/// Example: "example.com" -> [7]example[3]com[0]
pub fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Handle root domain
    if name == "." {
        encoded.push(0);
        return encoded;
    }

    // Split domain into labels and encode each
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }

        let label_bytes = label.as_bytes();
        if label_bytes.len() > 63 {
            // DNS labels are limited to 63 bytes
            panic!("Label too long: {}", label);
        }

        encoded.push(label_bytes.len() as u8);
        encoded.extend_from_slice(label_bytes);
    }

    // Null terminator
    encoded.push(0);

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain_name() {
        let encoded = encode_domain_name("example.com");
        assert_eq!(
            encoded,
            vec![7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
    }

    #[test]
    fn test_encode_root_domain() {
        let encoded = encode_domain_name(".");
        assert_eq!(encoded, vec![0]);
    }

    #[test]
    fn test_parse_domain_name() {
        let bytes = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let (name, offset) = parse_domain_name(&bytes, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(offset, 13);
    }

    #[test]
    fn test_dns_question_roundtrip() {
        let question = DnsQuestion {
            name: "example.com".to_string(),
            qtype: RecordType::A.to_u16(),
            qclass: RecordClass::IN.to_u16(),
        };

        let bytes = question.to_bytes();
        let (parsed, _) = DnsQuestion::from_bytes(&bytes, 0).unwrap();

        assert_eq!(parsed.name, question.name);
        assert_eq!(parsed.qtype, question.qtype);
        assert_eq!(parsed.qclass, question.qclass);
    }

    #[test]
    fn test_dns_answer_a_record() {
        let answer = DnsAnswer::new_a_record("example.com".to_string(), 60, [8, 8, 8, 8]);

        assert_eq!(answer.rtype, RecordType::A.to_u16());
        assert_eq!(answer.rclass, RecordClass::IN.to_u16());
        assert_eq!(answer.ttl, 60);
        assert_eq!(answer.rdata, vec![8, 8, 8, 8]);
        assert_eq!(answer.rdlength, 4);
    }

    #[test]
    fn test_dns_answer_roundtrip() {
        let answer = DnsAnswer::new_a_record("example.com".to_string(), 60, [192, 168, 1, 1]);

        let bytes = answer.to_bytes();
        let (parsed, _) = DnsAnswer::from_bytes(&bytes, 0).unwrap();

        assert_eq!(parsed.name, answer.name);
        assert_eq!(parsed.rtype, answer.rtype);
        assert_eq!(parsed.rclass, answer.rclass);
        assert_eq!(parsed.ttl, answer.ttl);
        assert_eq!(parsed.rdata, answer.rdata);
    }
}
