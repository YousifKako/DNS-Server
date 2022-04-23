use crate::packet_buffer::PacketBuffer;
use crate::dns_result_code::ResultCode;

#[derive(Debug)]
pub struct DnsHeader {
    pub packet_identifier:    u16,

    pub recursion_desired:    bool,
    pub truncated_message:    bool,
    pub authoritative_answer: bool,
    pub operation_code:       u8,
    pub query_response:       bool,

    pub response_code:        ResultCode,
    pub checking_disabled:    bool,
    pub authed_data:          bool,
    pub reserved:             bool,
    pub recursion_available:  bool,

    pub question_count:       u16,
    pub answer_count:         u16,
    pub authority_count:      u16,
    pub additional_count:     u16,
}

impl DnsHeader {
    pub fn new() -> Self {
        Self {
            packet_identifier:    0,
            recursion_desired:    false,
            truncated_message:    false,
            authoritative_answer: false,
            operation_code:       0,
            query_response:       false,
            response_code:        ResultCode::NOERROR,
            checking_disabled:    false,
            authed_data:          false,
            reserved:             false,
            recursion_available:  false,
            question_count:       0,
            answer_count:         0,
            authority_count:      0,
            additional_count:     0,
        }
    }

    pub fn read(&mut self, buffer: &mut PacketBuffer) {
        self.packet_identifier      = buffer.read_u16();

        let flag                    = buffer.read_u16();
        let left                    = (flag >> 8) as u8;
        let right                   = (flag & 0xFF) as u8;
        self.query_response         = (left & (1 << 7)) > 0;
        self.operation_code         = (left >> 1) & 0x0F;
        self.authoritative_answer   = (left & (1 << 2)) > 0;
        self.truncated_message      = (left & (1 << 1)) > 0;
        self.recursion_desired      = (left & (1 << 0)) > 0;

        self.recursion_available    = (right & (1 << 7)) > 0;
        self.reserved               = (right & (1 << 6)) > 0;
        self.authed_data            = (right & (1 << 5)) > 0;
        self.checking_disabled      = (right & (1 << 4)) > 0;
        self.response_code          = ResultCode::from_num(right & 0x0F);

        self.question_count         = buffer.read_u16();
        self.answer_count           = buffer.read_u16();
        self.authority_count        = buffer.read_u16();
        self.additional_count       = buffer.read_u16();
    }

    pub fn write(&self, buffer: &mut PacketBuffer) {
        buffer.write_u16(self.packet_identifier);

        buffer.write_u8((self.recursion_desired as u8)
                            | ((self.truncated_message as u8) << 1)
                            | ((self.authoritative_answer as u8) << 2)
                            | (self.operation_code << 3)
                            | ((self.query_response as u8) << 7));

        buffer.write_u8((self.response_code as u8)
                            | ((self.checking_disabled as u8) << 4)
                            | ((self.authed_data as u8) << 5)
                            | ((self.reserved as u8) << 6)
                            | ((self.recursion_available as u8) << 7));

        buffer.write_u16(self.question_count);
        buffer.write_u16(self.answer_count);
        buffer.write_u16(self.authority_count);
        buffer.write_u16(self.additional_count);
    }
}