



pub struct DnsPacket {
    header: DnsHeader,
    question: QuestionSection,
    answer: AnswerSection,
}

#[derive(Debug)]
pub struct DnsHeader {
                                        /*   https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1   */
                                        /*   https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format   <-- The header format here is current   */ 

    pub id: u16,                            // Transaction ID: 16 bits - A random ID assigned to query packets. Response packets must reply with the same ID.
                                         // Flags: 16 bits
    pub query_indicator: bool,              // QR: 1 bit - Indicates if the message is a query (0) or a reply (1).
    pub opcode: u8,                         // OPCODE: 4 bits - The type can be QUERY (standard query, 0), IQUERY (inverse query, 1), or STATUS (server status request, 2).
    pub authoritative_answer: bool,         // AA: 1 bit - Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname.
    pub truncation: bool,                   // TC: 1 bit - TrunCation, indicates that this message was truncated due to excessive length.
    pub recursion_desired: bool,            // RD: 1 bit - Recursion Desired, indicates if the client means a recursive query.
    pub recursion_available: bool,          // RA: 1 bit - Recursion Available, in a response, indicates if the replying DNS server supports recursion.
    pub reserved: bool,                     // Z:  1 bit; (Z) == 0 - Zero, reserved for future use -> Now used for DNSSEC.
    pub authentic_data: bool,               // AD: 1 bit - Authentic Data, in a response, indicates if the replying DNS server verified the data.
    pub check_disabled: bool,               // CD: 1 bit - Checking Disabled, in a query, indicates that non-verified data is acceptable in a response.
    pub response_code: u8,                  // RCODE: 4 bits - Response code, can be NOERROR (0), FORMERR (1, Format error), SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.

    pub question_count: u16,                // Number of Questions: 16 bits
    pub answer_record_count: u16,           // Number of Answers: 16 bits
    pub authority_record_count: u16,        // Number of Authority RRs: 16 bits
    pub additional_record_count: u16,       // Number of Additional RRs: 16 bits
}

impl DnsHeader {
    const DNS_HEADER_LEN:usize = 12;

    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0x00,                          
    
            query_indicator: false,              
            opcode: 0,                         
            authoritative_answer: false,               
            truncation: false,                   
            recursion_desired: false,            
            recursion_available: false,          
            reserved: false,                       
            authentic_data: false,               
            check_disabled: false,               
            response_code: 0,                  
    
            question_count: 0,                
            answer_record_count: 0,           
            authority_record_count: 0,        
            additional_record_count: 0, 
        }
    }

    /// Convert each field of the DnsHeader struct to a Big Endian byte vector
    pub fn serialize_to_bytes(&self) -> Vec<u8> {
        
        let mut buffer_vec = Vec::with_capacity(DnsHeader::DNS_HEADER_LEN);

        buffer_vec.extend_from_slice(&self.id.to_be_bytes());     // u16 to big endian bytes
        buffer_vec.push(
            ((self.query_indicator as u8) << 7)                   // Convert to u8 then shift the bit 7 places to the left (most significant bit) - if true: 00000001 << 7  becomes  10000000 
                | (self.opcode << 3)                              // shift the opcode(4 bits) left 3 bits and perform bitwise OR to the query_indicator bits 
                                                                    //(ex. with opcode=1:  10000000 | (00000001 << 3) => 10000000 | 00001000 => resulting OR => 10001000) 
                                                                    //                                         4 shifted opcode bits ^^^^                       ^   ^ significant bits remain after OR operation
                | ((self.authoritative_answer as u8) << 2)
                | ((self.truncation as u8) << 1)
                | self.recursion_desired as u8,
        );

        // The same bit wise operations and big endian convertions occur for the rest of the DnsHeader fields... 
        buffer_vec.push(
            ((self.recursion_available as u8) << 7)         // 00000001 <<7 => 10000000
                | ((self.reserved as u8) << 6)              // 00000001 <<6 => 01000000 | 10000000 => 11000000
                | ((self.authentic_data as u8) << 5)        // 00000001 <<5 => 00100000 | 11000000 => 11100000
                | ((self.check_disabled as u8) << 4)        // 00000001 <<4 => 00010000 | 11100000 => 11110000
                | self.response_code,                       //                                            ^^^^ the 4 bit response_code already has it's signficant bits in the lower 4 bits, so just OR 
        );

        // Append remaining header fields
        buffer_vec.extend_from_slice(&self.question_count.to_be_bytes());
        buffer_vec.extend_from_slice(&self.answer_record_count.to_be_bytes());
        buffer_vec.extend_from_slice(&self.authority_record_count.to_be_bytes());
        buffer_vec.extend_from_slice(&self.additional_record_count.to_be_bytes());


        buffer_vec
    }
}


/// The question section has a simpler format than the resource record format used in the other sections. Each question record (there is usually just one in the section)
pub struct QuestionSection {
    // The domain name is broken into discrete labels which are concatenated; each label is prefixed by the length of that label
    pub resource_record: ResourceRecord,
}   

impl QuestionSection {
    pub fn new() -> QuestionSection {
        QuestionSection { 
            resource_record: ResourceRecord::new()
            }
    }
    
    /// Given standard URL, Separate by '.' ; Get the length of the first label; place length in hex to the front; get length of second label (TDL); replace with length in hex; append null byte.
    /// example: google.com becomes: \x06google\x03com\x00
    pub fn to_label_sequence(&self) -> String {

        // <length><content>
        let domain_name = &self.resource_record.name;
        let split_domain_name: Vec<&str> = domain_name.split('.').collect();

        let mut label_sequence = String::new();

        for content_label in split_domain_name {
            // Get the length of the current label and convert it to hex (format: \x0b)
            let this_str_len = content_label.len();
            let length_label = format!("\\x{:02x}", this_str_len);  // Format the string as a 2 byte hex value

            // Append the length label and content label
            label_sequence += &length_label;
            label_sequence += content_label;
        }

        label_sequence += "\\x00";  // Append a null byte to the label sequence
        
        label_sequence
    }

    /// Convert each field of the QuestionSection struct to a Big Endian byte vector
    pub fn serialize_to_bytes(&self) -> Vec<u8> {

        let capacity = self.resource_record.name.len() + 32;    // Capacity is the length of the name + the 4 bytes of the record_type and record_class field 

        let mut buffer_vec: Vec<u8> = Vec::with_capacity(capacity);

        // Clone the name (which at this point should be a label) and convert it to bytes
        let name = self.resource_record.name.clone();
        let mut name_bytes = name.into_bytes();

        buffer_vec.append(&mut name_bytes);
    
        // Append remaining header fields
        buffer_vec.extend_from_slice(&self.resource_record.record_type.to_be_bytes());
        buffer_vec.extend_from_slice(&self.resource_record.class.to_be_bytes());

        buffer_vec
    }
}

pub struct ResourceRecord {
                            /*   https://en.wikipedia.org/wiki/Domain_Name_System#Resource_records   */
    pub name: String,               // [Variable size] Name of the node to which this record pertains
    pub record_type: u16,           // 2 byte 	Type of resource record in numeric form (e.g., 15 for MX RRs)
    pub class: u16,                 // 2 byte   class code
    pub ttl: u32,                   // 4 byte   Count of seconds that the RR stays valid (The maximum is 231−1, which is about 68 years)
    pub record_data_length: u16,    // 2 byte   Length of RDATA field (specified in octets)
    pub record_data: Vec<u8>,        // [Variable size] Additonal resource record specific data
}

impl ResourceRecord {

    pub fn new() -> ResourceRecord {
        ResourceRecord { 
            name: String::new(), 
            record_type: 1, 
            class: 0, 
            ttl: 0, 
            record_data_length: 0, 
            record_data: Vec::new()
        }
    }
}

pub struct AnswerSection {
    name: String,
    record_type: u16,
    class: u16,
    ttl: u32,
    length: u16,
    data: String,
}