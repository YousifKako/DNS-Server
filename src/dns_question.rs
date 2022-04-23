use crate::packet_buffer::PacketBuffer;
use crate::dns_query_type::QueryType;

#[derive(Debug)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(qname: String, qtype: QueryType) -> Self {
        Self {
            qname: qname,
            qtype: qtype,
        }
    }

    pub fn read(&mut self, buffer: &mut PacketBuffer) {
        self.qname = buffer.get_qname();
        self.qtype = QueryType::from_num(buffer.read_u16());
        let _      = buffer.read_u16(); // Class is always 1, discard this data
    }

    pub fn write(&self, buffer: &mut PacketBuffer) {
        buffer.write_qname(&self.qname);
        buffer.write_u16(self.qtype.to_num());
        buffer.write_u16(1);
    }
}