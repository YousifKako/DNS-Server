use crate::dns_header::DnsHeader;
use crate::dns_query_type::QueryType;
use crate::dns_question::DnsQuestion;
use crate::dns_record::DnsRecord;
use crate::packet_buffer::PacketBuffer;

pub struct DnsPacket
{
    pub header:            DnsHeader,
    pub question_section:  Vec<DnsQuestion>,
    pub answer_section:    Vec<DnsRecord>,
    pub authority_section: Vec<DnsRecord>,
    pub addition_section:  Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header:            DnsHeader::new(),
            question_section:  Vec::new(),
            answer_section:    Vec::new(),
            authority_section: Vec::new(),
            addition_section:  Vec::new(),
        }
    }

    pub fn get_packet_from_buffer(buffer: &mut PacketBuffer) -> Self {
        let mut result = Self::new();
        result.header.read(buffer);

        for _ in 0..result.header.question_count {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer);
            result.question_section.push(question);
        }

        for _ in 0..result.header.answer_count {
            let answer = DnsRecord::read(buffer);
            result.answer_section.push(answer);
        }

        for _ in 0..result.header.authority_count {
            let authority = DnsRecord::read(buffer);
            result.authority_section.push(authority);
        }

        for _ in 0..result.header.additional_count {
            let addition = DnsRecord::read(buffer);
            result.addition_section.push(addition);
        }

        return result;
    }

    pub fn write_packet_to_buffer(&mut self, buffer: &mut PacketBuffer) {
        self.header.write(buffer);

        for question in &self.question_section {
            question.write(buffer);
        }

        for answer in &self.answer_section {
            answer.write(buffer);
        }

        for authority in &self.authority_section {
            authority.write(buffer);
        }

        for addition in &self.addition_section {
            addition.write(buffer);
        }
    }
}