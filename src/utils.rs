use std::net::Ipv4Addr;

pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    let len = data.len();
    
    while i < len {
        let word = if i + 1 < len {
            ((data[i] as u16) << 8) | data[i + 1] as u16
        } else {
            (data[i] as u16) << 8
        };
        sum += word as u32;
        i += 2;
    }
    
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    !(sum as u16)
}

pub fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    let octets = ip.octets();
    ((octets[0] as u32) << 24) |
    ((octets[1] as u32) << 16) |
    ((octets[2] as u32) << 8)  |
    (octets[3] as u32)
}
