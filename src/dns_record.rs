use crate::packet_buffer::PacketBuffer;
use crate::dns_query_type::QueryType;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype:  u16,
        ttl:    u32,
        len:    u16,
    },
    A {
        domain: String,
        addr:   Ipv4Addr,
        ttl:    u32,
    }, // 1
    NS {
        domain: String,
        host:   String,
        ttl:    u32,
    }, // 2
    CNAME {
        domain: String,
        host:   String,
        ttl:    u32,
    }, // 5
    MX {
        domain:   String,
        priority: u16,
        host:     String,
        ttl:      u32,
    }, // 15
    AAAA {
        domain: String,
        addr:   Ipv6Addr,
        ttl:    u32,
    } // 28
}

impl DnsRecord {
    pub fn read(buffer: &mut PacketBuffer) -> Self {
        let domain = buffer.get_qname();
        let qtype  = buffer.read_u16();
        let _      = buffer.read_u16(); // Class is always 1, discard this data
        let ttl    = buffer.read_u32();
        let len    = buffer.read_u16();

        match qtype {
            1 => Self::A {
                domain: domain,
                addr: Ipv4Addr::new(
                    buffer.read(),
                    buffer.read(),
                    buffer.read(),
                    buffer.read(),
                ),
                ttl: ttl
            },
            2 => {
                let host = buffer.get_qname();
                Self::NS {
                    domain: domain,
                    host: host,
                    ttl: ttl
                }
            },
            5 => {
                let host = buffer.get_qname();
                Self::CNAME {
                    domain: domain,
                    host: host,
                    ttl: ttl
                }
            },
            15 => {
                let priority = buffer.read_u16();
                let host = buffer.get_qname();
                Self::MX {
                    domain: domain,
                    priority: priority,
                    host: host,
                    ttl: ttl
                }
            },
            28 => {
                Self::AAAA {
                    domain: domain,
                    addr: Ipv6Addr::new(
                        buffer.read_u16(),
                        buffer.read_u16(),
                        buffer.read_u16(),
                        buffer.read_u16(),
                        buffer.read_u16(),
                        buffer.read_u16(),
                        buffer.read_u16(),
                        buffer.read_u16(),
                    ),
                    ttl: ttl
                }
            },
            _ => {
                buffer.step_pos(len as usize);

                Self::UNKNOWN {
                    domain: domain,
                    qtype: qtype,
                    ttl: ttl,
                    len: len
                }
            }
        }
    }

    pub fn write(&self, buffer: &mut PacketBuffer) {
        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl
            } => {
                buffer.write_qname(domain);
                buffer.write_u16(QueryType::A.to_num());
                buffer.write_u16(1);
                buffer.write_u32(ttl);
                buffer.write_u16(4);

                let octets = addr.octets();
                buffer.write_u8(octets[0]);
                buffer.write_u8(octets[1]);
                buffer.write_u8(octets[2]);
                buffer.write_u8(octets[3]);
            },
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl
            } => {
                buffer.write_qname(domain);
                buffer.write_u16(QueryType::NS.to_num());
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                // We don't know ahead of time the number of bytes needed, since we might
                // end up using jumps to compress the size. We'll solve this by writing
                // a zero size and then going back to fill in the size needed.
                let pos = buffer.get_pos();
                buffer.write_u16(0);
                buffer.write_qname(host);

                let size = buffer.get_pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            },
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain);
                buffer.write_u16(QueryType::CNAME.to_num());
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                let pos = buffer.get_pos();
                buffer.write_u16(0);
                buffer.write_qname(host);

                let size = buffer.get_pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            },
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain);
                buffer.write_u16(QueryType::MX.to_num());
                buffer.write_u16(1);
                buffer.write_u32(ttl);

                let pos = buffer.get_pos();
                buffer.write_u16(0);
                buffer.write_u16(priority);
                buffer.write_qname(host);

                let size = buffer.get_pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            },
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain);
                buffer.write_u16(QueryType::AAAA.to_num());
                buffer.write_u16(1);
                buffer.write_u32(ttl);
                buffer.write_u16(16);

                for octet in &addr.segments() {
                    buffer.write_u16(*octet);
                }
            },
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping Record: {:?}", self);
            }
        }
    }
}