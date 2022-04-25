#[derive(Clone, Copy, Debug)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            Self::UNKNOWN(x) => x,
            Self::A          => 1,
            Self::NS         => 2,
            Self::CNAME      => 5,
            Self::MX         => 15,
            Self::AAAA       => 28,
        }
    }

    pub fn from_num(num: u16) -> Self {
        match num {
            1  => Self::A,
            2  => Self::NS,
            5  => Self::CNAME,
            15 => Self::MX,
            28 => Self::AAAA,
            _  => Self::UNKNOWN(num),
        }
    }
}