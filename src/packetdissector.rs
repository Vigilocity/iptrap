use std;
use std::mem::size_of;
use std::slice;

pub static ETHERTYPE_IP: u16 = 0x0800;
pub static IPPROTO_TCP: u8 = 6;
pub static TH_SYN: u8 = 0x02;
pub static TH_RST: u8 = 0x04;
pub static TH_ACK: u8 = 0x10;
pub static TH_PUSH: u8 = 0x08;

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct EtherHeader {
    pub ether_dhost: [u8; 6],
    pub ether_shost: [u8; 6],
    pub ether_type: u16,
}

#[repr(packed)]
#[derive(Copy, Clone)]
pub struct IpHeader {
    pub ip_vhl: u8,
    pub ip_tos: u8,
    pub ip_len: u16,
    pub ip_id: u16,
    pub ip_off: u16,
    pub ip_ttl: u8,
    pub ip_p: u8,
    pub ip_sum: u16,
    pub ip_src: [u8; 4],
    pub ip_dst: [u8; 4],
}

#[repr(packed)]
#[derive(Clone, Copy)]
pub struct TcpHeader {
    pub th_sport: u16,
    pub th_dport: u16,
    pub th_seq: u32,
    pub th_ack: u32,
    pub th_off_x2: u8,
    pub th_flags: u8,
    pub th_win: u16,
    pub th_sum: u16,
    pub th_urp: u16,
}

pub struct PacketDissectorFilter {
    local_ip: Vec<u8>,
}

impl PacketDissectorFilter {
    pub fn new(local_ip: Vec<u8>) -> PacketDissectorFilter {
        PacketDissectorFilter { local_ip }
    }
}

pub struct PacketDissector {
    pub ll_data: Vec<u8>,
    pub etherhdr_ptr: *const EtherHeader,
    pub iphdr_ptr: *const IpHeader,
    pub tcphdr_ptr: *const TcpHeader,
    pub tcp_data: Vec<u8>,
}

impl PacketDissector {
    pub fn new(filter: &PacketDissectorFilter, ll_data: Vec<u8>) -> Result<PacketDissector, &str> {
        let ll_data_len = ll_data.len();
        if ll_data_len < size_of::<EtherHeader>() {
            return Err("Short ethernet frame");
        }
        let ll_data_ptr = ll_data.as_ptr();
        let etherhdr_ptr: *const EtherHeader = ll_data_ptr as *const EtherHeader;
        let ref etherhdr = unsafe { *etherhdr_ptr };
        if etherhdr.ether_type != ETHERTYPE_IP.to_be() {
            return Err("Unsupported type of ethernet frame");
        }
        let iphdr_offset: usize = size_of::<EtherHeader>();
        if ll_data_len - iphdr_offset < size_of::<IpHeader>() {
            return Err("Short IP packet");
        }
        let iphdr_ptr: *const IpHeader =
            unsafe { ll_data_ptr.offset(iphdr_offset as isize) as *const IpHeader };
        let ref iphdr: IpHeader = unsafe { *iphdr_ptr };
        let iphdr_len = (iphdr.ip_vhl & 0xf) as usize * 4;
        if iphdr_len < size_of::<IpHeader>() || ll_data_len - iphdr_offset < iphdr_len {
            return Err("Short IP packet");
        }
        let ip_version = (iphdr.ip_vhl >> 4) & 0xf;
        if ip_version != 4 {
            return Err("Unsupported IP version");
        }
        if iphdr.ip_p != IPPROTO_TCP {
            return Err("Unsupported IP protocol");
        }
        if filter.local_ip.ne(&iphdr.ip_dst.to_vec()) {
            return Err("Packet destination is not the local IP");
        }
        let tcphdr_offset = iphdr_offset + iphdr_len;
        if ll_data_len - tcphdr_offset < size_of::<TcpHeader>() {
            return Err("Short TCP packet");
        }
        let tcphdr_ptr: *const TcpHeader =
            unsafe { ll_data_ptr.offset(tcphdr_offset as isize) as *const TcpHeader };
        let ref tcphdr: TcpHeader = unsafe { *tcphdr_ptr };
        let tcphdr_data_offset = ((tcphdr.th_off_x2 >> 4) & 0xf) as usize * 4;
        if tcphdr_data_offset < size_of::<TcpHeader>() {
            return Err("Short TCP data offset");
        }
        if ll_data_len - tcphdr_offset < tcphdr_data_offset {
            return Err("Truncated TCP packet - no data");
        }
        let tcp_data_offset = tcphdr_offset + tcphdr_data_offset;

        let ip_len = u16::from_be(iphdr.ip_len) as usize;
        if ip_len < tcp_data_offset - tcp_data_offset {
            return Err("Truncated TCP packet - truncated data");
        }
        let real_tcp_data_len = ip_len - iphdr_len - tcphdr_data_offset;
        let max_tcp_data_len = ll_data_len - tcp_data_offset;
        let tcp_data_len = std::cmp::min(real_tcp_data_len, max_tcp_data_len);
        let tcp_data_ptr = unsafe { ll_data_ptr.offset(tcp_data_offset as isize) };
        let tcp_data =
            unsafe { slice::from_raw_parts(tcp_data_ptr as *mut u8, tcp_data_len) }.to_vec();
        Ok(PacketDissector {
            ll_data,
            etherhdr_ptr,
            iphdr_ptr,
            tcphdr_ptr,
            tcp_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ethernet_header(ether_type: u16) -> Vec<u8> {
        let mut header = vec![0u8; 14];
        // dst MAC: 00:11:22:33:44:55
        header[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        // src MAC: 66:77:88:99:aa:bb
        header[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        // EtherType (big-endian)
        header[12..14].copy_from_slice(&ether_type.to_be_bytes());
        header
    }

    fn build_ip_header(src: [u8; 4], dst: [u8; 4], protocol: u8, total_len: u16) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        header[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        header[1] = 0x00; // TOS
        header[2..4].copy_from_slice(&total_len.to_be_bytes()); // Total length
        header[4..6].copy_from_slice(&[0x00, 0x01]); // ID
        header[6..8].copy_from_slice(&[0x00, 0x00]); // Flags + Fragment offset
        header[8] = 64; // TTL
        header[9] = protocol; // Protocol
        header[10..12].copy_from_slice(&[0x00, 0x00]); // Checksum (not validated)
        header[12..16].copy_from_slice(&src); // Source IP
        header[16..20].copy_from_slice(&dst); // Dest IP
        header
    }

    fn build_tcp_header(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        header[0..2].copy_from_slice(&src_port.to_be_bytes()); // Source port
        header[2..4].copy_from_slice(&dst_port.to_be_bytes()); // Dest port
        header[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Seq
        header[8..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Ack
        header[12] = 0x50; // Data offset: 5 (20 bytes), no options
        header[13] = flags; // Flags
        header[14..16].copy_from_slice(&[0xff, 0xff]); // Window
        header[16..18].copy_from_slice(&[0x00, 0x00]); // Checksum
        header[18..20].copy_from_slice(&[0x00, 0x00]); // Urgent pointer
        header
    }

    fn build_test_packet(local_ip: [u8; 4], src_ip: [u8; 4], dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let ip_total_len = 20 + tcp_len;

        let mut packet = build_ethernet_header(ETHERTYPE_IP);
        packet.extend(build_ip_header(src_ip, local_ip, IPPROTO_TCP, ip_total_len as u16));
        packet.extend(build_tcp_header(54321, dst_port, TH_ACK));
        packet.extend(payload);
        packet
    }

    #[test]
    fn test_valid_packet_with_payload() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip.clone());
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let packet = build_test_packet([10, 0, 0, 1], [192, 168, 1, 100], 80, payload);

        let dissector = PacketDissector::new(&filter, packet).expect("Should parse valid packet");

        assert_eq!(dissector.tcp_data, payload.to_vec());
        let tcphdr = unsafe { &*dissector.tcphdr_ptr };
        assert_eq!(u16::from_be(tcphdr.th_dport), 80);
        assert_eq!(u16::from_be(tcphdr.th_sport), 54321);
    }

    #[test]
    fn test_empty_payload() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip);
        let packet = build_test_packet([10, 0, 0, 1], [192, 168, 1, 100], 443, &[]);

        let dissector = PacketDissector::new(&filter, packet).expect("Should parse packet with empty payload");

        assert!(dissector.tcp_data.is_empty());
    }

    #[test]
    fn test_binary_payload() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip);
        // TLS Client Hello starts with 0x16 0x03
        let payload: Vec<u8> = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        let packet = build_test_packet([10, 0, 0, 1], [192, 168, 1, 100], 443, &payload);

        let dissector = PacketDissector::new(&filter, packet).expect("Should parse binary payload");

        assert_eq!(dissector.tcp_data, payload);
    }

    #[test]
    fn test_wrong_destination_ip() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip);
        // Packet destined for different IP
        let packet = build_test_packet([10, 0, 0, 2], [192, 168, 1, 100], 80, b"test");

        let result = PacketDissector::new(&filter, packet);

        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Packet destination is not the local IP");
    }

    #[test]
    fn test_non_ip_ethertype() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip);
        let packet = build_ethernet_header(0x86DD); // IPv6

        let result = PacketDissector::new(&filter, packet);

        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Unsupported type of ethernet frame");
    }

    #[test]
    fn test_non_tcp_protocol() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip);

        let mut packet = build_ethernet_header(ETHERTYPE_IP);
        packet.extend(build_ip_header([192, 168, 1, 100], [10, 0, 0, 1], 17, 28)); // UDP (17)

        let result = PacketDissector::new(&filter, packet);

        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Unsupported IP protocol");
    }

    #[test]
    fn test_short_ethernet_frame() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip);
        let packet = vec![0u8; 10]; // Too short

        let result = PacketDissector::new(&filter, packet);

        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Short ethernet frame");
    }

    #[test]
    fn test_short_ip_packet() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip);
        let mut packet = build_ethernet_header(ETHERTYPE_IP);
        packet.extend(vec![0u8; 10]); // Short IP header

        let result = PacketDissector::new(&filter, packet);

        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_flags_preserved() {
        let local_ip = vec![10, 0, 0, 1];
        let filter = PacketDissectorFilter::new(local_ip.clone());

        let ip_total_len = 20 + 20; // IP header + TCP header, no payload
        let mut packet = build_ethernet_header(ETHERTYPE_IP);
        packet.extend(build_ip_header([192, 168, 1, 100], [10, 0, 0, 1], IPPROTO_TCP, ip_total_len as u16));
        packet.extend(build_tcp_header(54321, 443, TH_SYN | TH_ACK));

        let dissector = PacketDissector::new(&filter, packet).expect("Should parse");
        let tcphdr = unsafe { &*dissector.tcphdr_ptr };

        assert_eq!(tcphdr.th_flags, TH_SYN | TH_ACK);
    }
}
