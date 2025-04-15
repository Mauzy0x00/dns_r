/*
*   Purpose: Continue to practice Rust and learn more about DNS
*   Author: Mauzy0x00
*   Start Date: 04-10-2025
*/

use std::net::UdpSocket;

mod dns;
use dns::*;



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

    // Setup question section
    let domain_name = "google.com";
    let mut question = QuestionSection::new();
    let mut answer = AnswerSection::new();

    // Add the domain name to the name field and convert it to a label sequence
    question.resource_record.name = domain_name.to_string();
    question.resource_record.name = question.to_label_sequence();
    question.resource_record.record_type = 1;
    question.resource_record.class = 1;

    println!("Question name label: {}", question.resource_record.name);

    // Serialize the data and send to the client
    let mut serialized_response = default_response.serialize_to_bytes();
    serialized_response.append(&mut question.serialize_to_bytes());     // Append the QuestionSection to the response

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
