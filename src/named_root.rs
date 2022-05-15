use std::fs;
use rand::Rng;

pub struct NamedRoot {
    pub domain: String,
    pub ipv4:   String,
    pub ipv6:   String,
}

impl NamedRoot {
    fn new(domain: &str, ipv4: &str, ipv6: &str) -> Self {
        let mut domain = domain.to_string();
        domain.pop();

        Self {
            domain: domain,
            ipv4:   ipv4.to_string(),
            ipv6:   ipv6.to_string(),
        }
    }
    
    pub fn get_named_root() -> Self {
        let file             = fs::read_to_string("assets/named.root.txt").unwrap();
        let lines: Vec<&str> = file.split("\n").collect();

        let named_root_to_select   = rand::thread_rng().gen_range(0..13);
        let mut current_named_root = 0;

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let chr  = line.as_bytes()[0];
            if chr == ('.' as u8) {
                if named_root_to_select == current_named_root {
                    let ipv4: Vec<&str> = lines[i+1].split_whitespace().collect();
                    let ipv6: Vec<&str> = lines[i+2].split_whitespace().collect();
                    
                    return NamedRoot::new(ipv4[0], ipv4[3], ipv6[3]);
                }

                current_named_root += 1;
                i += 2;
            }

            i += 1;
        }

        return NamedRoot::new("", "", "");
    }
}