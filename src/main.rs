/*
*   Purpose: Continue to practice Rust and learn more about DNS
*   Author: Mauzy0x00
*   Start Date: 04-10-2025
*/

use std::net::UdpSocket;

#[derive(Debug)]
struct DnsHeader {
                                        /*   https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1   */
                                        /*   https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format   <-- The header format here is current   */ 

    id: u16,                            // Transaction ID: 16 bits - A random ID assigned to query packets. Response packets must reply with the same ID.
                                    // Flags: 16 bits
    query_indicator: bool,              // QR: 1 bit - Indicates if the message is a query (0) or a reply (1).
    opcode: u8,                         // OPCODE: 4 bits - The type can be QUERY (standard query, 0), IQUERY (inverse query, 1), or STATUS (server status request, 2).
    authoritative_answer: bool,         // AA: 1 bit - Authoritative Answer, in a response, indicates if the DNS server is authoritative for the queried hostname.
    truncation: bool,                   // TC: 1 bit - TrunCation, indicates that this message was truncated due to excessive length.
    recursion_desired: bool,            // RD: 1 bit - Recursion Desired, indicates if the client means a recursive query.
    recursion_available: bool,          // RA: 1 bit - Recursion Available, in a response, indicates if the replying DNS server supports recursion.
    reserved: bool,                     // Z:  1 bit; (Z) == 0 - Zero, reserved for future use -> Now used for DNSSEC.
    authentic_data: bool,               // AD: 1 bit - Authentic Data, in a response, indicates if the replying DNS server verified the data.
    check_disabled: bool,               // CD: 1 bit - Checking Disabled, in a query, indicates that non-verified data is acceptable in a response.
    response_code: u8,                  // RCODE: 4 bits - Response code, can be NOERROR (0), FORMERR (1, Format error), SERVFAIL (2), NXDOMAIN (3, Nonexistent domain), etc.

    question_count: u16,                // Number of Questions: 16 bits
    answer_record_count: u16,           // Number of Answers: 16 bits
    authority_record_count: u16,        // Number of Authority RRs: 16 bits
    additional_record_count: u16,       // Number of Additional RRs: 16 bits
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
struct QuestionSection {
    // The domain name is broken into discrete labels which are concatenated; each label is prefixed by the length of that label
    name: String,          // The domain name, encoded as a sequence of labels
    record_type: u16,      // 2 byte integer that defines the record type : Type of RR (A, AAAA, MX, TXT, etc.)
}   

impl QuestionSection {
    pub fn new() -> QuestionSection {
        QuestionSection { name: String::new(), record_type: 0}
    }

    pub fn to_label_sequence(mut self) -> String {

        // Separate domain name by '.' ; Get length of the first label; place length in hex to the front; get length of second label (TDL); replace with length in hex; append null byte
        // <length><content>
        let domain_name = &self.name;
        let split_domain_name: Vec<&str> = domain_name.split('.').collect();

        let mut label_sequence = String::new();

        for content_label in split_domain_name {
            // Get the length of the current label and convert it to hex (format: \x0b)
            let this_str_len = content_label.len();
            let length_label = format!("\\x{:x}", this_str_len);

            // Append the length label and content label
            label_sequence += &length_label;
            label_sequence += content_label;
        }

        label_sequence += "\\x00";  // Append a null byte to the label sequence
        self.name = label_sequence;

        self.name
    }
}

// struct ResourceRecord {
//                             /*   https://en.wikipedia.org/wiki/Domain_Name_System#Resource_records   */
//     name: String,               // [Variable size] Name of the node to which this record pertains
//     record_type: RecordType,    // 2 byte 	Type of resource record in numeric form (e.g., 15 for MX RRs)
//     class: u16,                 // 2 byte   class code
//     ttl: u32,                   // 4 byte   Count of seconds that the RR stays valid (The maximum is 231−1, which is about 68 years)
//     record_data_length: u16,    // 2 byte   Length of RDATA field (specified in octets)
//     record_data: String,        // [Variable size] Additonal resource record specific data
// }

// impl ResourceRecord {

//     pub fn new() -> ResourceRecord {
//         ResourceRecord { 
//             name: String::new(), 
//             record_type: RecordType::A, 
//             class: 0, 
//             ttl: 0, 
//             record_data_length: 0, 
//             record_data: String::new() 
//         }
//     }
// }

// enum RecordType {
    // A,               //1 a host address
    // NS,              //2 an authoritative name server
    // MD,              //3 a mail destination (Obsolete - use MX)
    // MF,              // 4 a mail forwarder (Obsolete - use MX)
    // CNAME,           // 5 the canonical name for an alias
    // SOA,             // 6 marks the start of a zone of authority
    // MB,              // 7 a mailbox domain name (EXPERIMENTAL)
    // MG,              // 8 a mail group member (EXPERIMENTAL)
    // MR,              // 9 a mail rename domain name (EXPERIMENTAL)
    // NULL,            // 10 a null RR (EXPERIMENTAL)
    // WKS,             // 11 a well known service description
    // PTR,             // 12 a domain name pointer
    // HINFO,           // 13 host information
    // MINFO,           // 14 mailbox or mail list information
    // MX,              // 15 mail exchange
    // TXT,             // 16 text strings
// }


fn main() -> std::io::Result<()> {
    
    let socket = UdpSocket::bind("127.0.0.1:2053")?;
    
    // Receives a single datagram message on the socket. If the buffer is too small to hold the message it will be cut off
    let mut recv_buffer = [0; 1024];
    let (number_of_bytes, source_address) = socket.recv_from(&mut recv_buffer).expect("Didn't recieve data...");


    // Create a new DNS Header
    let mut default_response = DnsHeader::new();

    // Hard code packet testing values
    default_response.id = 1234;
    default_response.query_indicator = true;
    default_response.question_count = 1;


    let mut question = QuestionSection::new();
    question.record_type = 1;

    // Serialize the data and send to the client
    let serialized_response = default_response.serialize_to_bytes();

    display_sent_values(&serialized_response);

    socket.send_to(&serialized_response, source_address).expect("Couldn't send data");

    Ok(())
}


fn display_sent_values(serialized_response: &[u8]) {

    let mut binary_string = String::new();
    for byte in serialized_response {
        binary_string += &format!("{byte:0>8b} ");
    }
    
    println!("Sending: {}", binary_string);             // Display serialized data as a binary string
    println!("Sending: {:X?}", serialized_response);    // Display serialized data as hex bytes
    println!("Sending: {:?}", serialized_response);     // Display serialized data as integers
}
