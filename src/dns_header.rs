#[derive(Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct DnsFlags {
    pub qr: bool,              // Query/Response (false = query, true = response)
    pub opcode: u8,            // Operation code (0 = standard query)
    pub aa: bool,              // Authoritative Answer
    pub tc: bool,              // Truncation
    pub rd: bool,              // Recursion Desired
    pub ra: bool,              // Recursion Available
    pub z: u8,                 // Reserved (must be 0)
    pub rcode: u8,             // Response code (0 = no error, 1 = format error, etc.)
}

impl DnsFlags {
    pub fn to_u16(&self) -> u16 {
        let mut flags: u16 = 0;
        
        if self.qr { flags |= 1 << 15; }           // QR at bit 15
        flags |= (self.opcode as u16 & 0xF) << 11; // OPCODE at bits 11-14
        if self.aa { flags |= 1 << 10; }           // AA at bit 10
        if self.tc { flags |= 1 << 9; }            // TC at bit 9
        if self.rd { flags |= 1 << 8; }            // RD at bit 8
        if self.ra { flags |= 1 << 7; }            // RA at bit 7
        flags |= (self.z as u16 & 0x7) << 4;       // Z at bits 4-6 (reserved)
        flags |= self.rcode as u16 & 0xF;          // RCODE at bits 0-3
        
        flags
    }
    
    pub fn from_u16(flags: u16) -> Self {
        DnsFlags {
            qr: (flags & (1 << 15)) != 0,
            opcode: ((flags >> 11) & 0xF) as u8,
            aa: (flags & (1 << 10)) != 0,
            tc: (flags & (1 << 9)) != 0,
            rd: (flags & (1 << 8)) != 0,
            ra: (flags & (1 << 7)) != 0,
            z: ((flags >> 4) & 0x7) as u8,
            rcode: (flags & 0xF) as u8,
        }
    }
}

impl DnsHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 12 {
            return Err("Buffer too small for DNS header");
        }

        Ok(DnsHeader {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            question_count: u16::from_be_bytes([bytes[4], bytes[5]]),
            answer_count: u16::from_be_bytes([bytes[6], bytes[7]]),
            authority_count: u16::from_be_bytes([bytes[8], bytes[9]]),
            additional_count: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];

        let id_bytes = self.id.to_be_bytes();
        bytes[0] = id_bytes[0];
        bytes[1] = id_bytes[1];

        let flags_bytes = self.flags.to_be_bytes();
        bytes[2] = flags_bytes[0];
        bytes[3] = flags_bytes[1];

        let question_count_bytes = self.question_count.to_be_bytes();
        bytes[4] = question_count_bytes[0];
        bytes[5] = question_count_bytes[1];

        let answer_count_bytes = self.answer_count.to_be_bytes();
        bytes[6] = answer_count_bytes[0];
        bytes[7] = answer_count_bytes[1];

        let authority_count_bytes = self.authority_count.to_be_bytes();
        bytes[8] = authority_count_bytes[0];
        bytes[9] = authority_count_bytes[1];

        let additional_count_bytes = self.additional_count.to_be_bytes();
        bytes[10] = additional_count_bytes[0];
        bytes[11] = additional_count_bytes[1];

        bytes
    }
}
