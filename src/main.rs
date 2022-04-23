mod packet_buffer;
mod dns_packet;
mod dns_header;
mod dns_question;
mod dns_record;
mod dns_query_type;
mod dns_result_code;

use std::net::UdpSocket;
use dns_packet::DnsPacket;
use dns_query_type::QueryType;
use packet_buffer::PacketBuffer;

fn main() {
    let qname  = "yahoo.com";
    let qtype  = QueryType::MX;
    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 8888)).unwrap();

    let mut packet                  = dns_packet::DnsPacket::new();
    packet.header.packet_identifier = 6666;
    packet.header.question_count    = 1;
    packet.header.recursion_desired = true;
    packet
        .question_section
        .push(dns_question::DnsQuestion::new(qname.to_string(), qtype));

    let mut request_buffer = PacketBuffer::new();
    packet.write_packet_to_buffer(&mut request_buffer);
    
    socket.send_to(&request_buffer.buff[0..request_buffer.get_pos()], server).unwrap();

    let mut response_buffer = PacketBuffer::new();
    socket.recv_from(&mut response_buffer.buff).unwrap();

    let response_packet = DnsPacket::get_packet_from_buffer(&mut response_buffer);

    print_dns_packet(&response_packet);
}

fn print_dns_packet(dns_packet: &dns_packet::DnsPacket) {
    println!("Header");
    println!("{:#?}", dns_packet.header);

    println!("Questions");
    for question in &dns_packet.question_section {
        println!("{:#?}", question);
    }

    println!("Answers");
    for answer in &dns_packet.answer_section {
        println!("{:#?}", answer);
    }

    println!("Authority");
    for authority in &dns_packet.authority_section {
        println!("{:#?}", authority);
    }

    println!("Additional");
    for addition in &dns_packet.addition_section {
        println!("{:#?}", addition);
    }
}