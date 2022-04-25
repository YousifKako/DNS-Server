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
use dns_result_code::ResultCode;

fn main() {
    let socket = UdpSocket::bind(("0.0.0.0", 8888)).unwrap();

    loop {
        handle_query(&socket);
    }

}

fn handle_query(socket: &UdpSocket) {
    let mut request_buffer = PacketBuffer::new();
    let (_, src)           = socket.recv_from(&mut request_buffer.buff).unwrap();
    let mut request_packet = DnsPacket::get_packet_from_buffer(&mut request_buffer);

    let mut response_packet                    = DnsPacket::new();
    response_packet.header.packet_identifier   = request_packet.header.packet_identifier;
    response_packet.header.recursion_desired   = true;
    response_packet.header.recursion_available = true;
    response_packet.header.query_response      = true;

    if let Some(question) = request_packet.question_section.pop() {
        println!("Received Query: {:?}", question);

        if let Ok(result) = lookup(&question.qname, question.qtype) {
            response_packet.question_section.push(question);
            response_packet.header.response_code = result.header.response_code;

            for answer in result.answer_section {
                println!("Answer: {:?}", answer);
                response_packet.answer_section.push(answer);
            }

            for authority in result.authority_section {
                println!("Authority: {:?}", authority);
                response_packet.authority_section.push(authority);
            }

            for addition in result.additional_section {
                println!("Addition: {:?}", addition);
                response_packet.additional_section.push(addition);
            }
        } else {
            response_packet.header.response_code = ResultCode::SERVFAIL;
        }
    } else {
        response_packet.header.response_code = ResultCode::FORMERR;
    }

    let mut response_buffer = PacketBuffer::new();
    response_packet.write_packet_to_buffer(&mut response_buffer);

    let data_len = response_buffer.get_pos();
    let data     = response_buffer.get_range(0, data_len);
    socket.send_to(data, src).unwrap();
}

fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket, ()> {
    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 12340)).unwrap();

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

    return Ok(DnsPacket::get_packet_from_buffer(&mut response_buffer));
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
    for addition in &dns_packet.additional_section {
        println!("{:#?}", addition);
    }
}