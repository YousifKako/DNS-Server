pub struct PacketBuffer {
    pub buff: [u8; 512],
    pos: usize,
}

impl PacketBuffer {
    pub fn new() -> Self {
        Self {
            buff: [0; 512],
            pos: 0,
        }
    }

    pub fn get_pos(&self) -> usize {
        return self.pos;
    }

    fn get_range(&mut self, start: usize, len: usize) -> &[u8] {
        if start + len >= 512 {
            return &self.buff[start..start];
        }

        return &self.buff[start..start + len as usize];
    }

    fn set(&mut self, pos: usize, val: u8) {
        if pos < 512 {
            self.buff[pos] = val;
        }
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) {
        self.set(pos, (val >> 8) as u8);
        self.set(pos + 1, (val & 0xFF) as u8);
    }

    pub fn set_pos(&mut self, new_pos: usize) {
        self.pos = new_pos;
    }

    pub fn step_pos(&mut self, step_pos: usize) {
        self.pos += step_pos;
    }

    fn write(&mut self, data: u8) {
        self.buff[self.pos] = data;

        if self.pos < 512 {
            self.pos += 1;
        }
    }

    pub fn write_u8(&mut self, data: u8) {
        self.write(data);
    }

    pub fn write_u16(&mut self, data: u16) {
        self.write((data >> 8) as u8);
        self.write((data & 0xFF) as u8);
    }

    pub fn write_u32(&mut self, data: u32) {
        self.write(((data >> 24) & 0xFF) as u8);
        self.write(((data >> 16) & 0xFF) as u8);
        self.write(((data >> 8) & 0xFF) as u8);
        self.write(((data >> 0) & 0xFF) as u8);
    }

    pub fn read(&mut self) -> u8 {
        if self.pos >= 512 {
            return self.buff[self.pos];
        }

        let buff = self.buff[self.pos];
        self.pos += 1;

        return buff;
    }

    pub fn read_u16(&mut self) -> u16 {
        let result = (self.read() as u16) << 8 | (self.read() as u16);
        return result;
    }

    pub fn read_u32(&mut self) -> u32 {
        let result = (self.read_u16() as u32) << 16 | (self.read_u16() as u32);
        return result;
    }

    pub fn get_qname(&mut self) -> String {
        let mut qname = String::new();
        let mut pos   = self.get_pos();

        let mut jumped          = false;
        let max_jumps           = 5;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop {
            if jumps_performed > max_jumps {
                break;
            }

            let len = self.buff[pos];
            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.set_pos(pos + 2);
                }

                let b2     = self.buff[pos + 1] as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos        = offset as usize;

                jumped           = true;
                jumps_performed += 1;

                continue;
            }
            else {
                pos += 1;
                if len == 0 {
                    break;
                }

                qname.push_str(delim);
                let str_buffer = self.get_range(pos, len as usize);
                qname.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";
                pos  += len as usize;
            }
        }

        if !jumped {
            self.set_pos(pos);
        }

        return qname;
    }

    pub fn write_qname(&mut self, qname: &str) {
        for label in qname.split('.') {
            self.write_u8(label.len() as u8);

            for byte in label.as_bytes() {
                self.write_u8(*byte);
            }
        }

        self.write_u8(0);
    }
}