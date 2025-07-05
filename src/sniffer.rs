use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::Packet;
use std::time::SystemTime;
use crossbeam_channel::Sender;
use std::fmt;

#[derive(Debug)]
pub struct PacketInfo {
    pub timestamp: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: usize,
    pub info: String,
}

impl PacketInfo {
    fn new() -> Self {
        Self {
            timestamp: String::new(),
            source: String::new(),
            destination: String::new(),
            protocol: String::new(),
            length: 0,
            info: String::new(),
        }
    }
}

pub struct PacketSniffer {
    interface: pnet_datalink::NetworkInterface,
    filter: String,
}

impl PacketSniffer {
    pub fn new(interface_name: &str, filter: &str) -> Self {
        let interface = pnet_datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .expect("Interface not found");
        
        Self {
            interface,
            filter: filter.to_string(),
        }
    }
    
    pub fn start(&mut self, tx: Sender<PacketInfo>) {
        let (_, mut rx) = match pnet_datalink::channel(&self.interface, pnet_datalink::Config::default()) {
            Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unsupported channel type"),
            Err(e) => panic!("Error creating channel: {}", e),
        };
        
        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Some(packet_info) = self.process_packet(&packet) {
                        tx.send(packet_info).unwrap();
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    break;
                }
            }
        }
    }
    
    fn process_packet(&self, packet: &[u8]) -> Option<PacketInfo> {
        let mut packet_info = PacketInfo::new();
        packet_info.timestamp = format!("{:?}", SystemTime::now());
        packet_info.length = packet.len();
        
        let ethernet = EthernetPacket::new(packet)?;
        
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4 = Ipv4Packet::new(ethernet.payload())?;
                packet_info.source = ipv4.get_source().to_string();
                packet_info.destination = ipv4.get_destination().to_string();
                
                match ipv4.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        packet_info.protocol = "TCP".to_string();
                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                            packet_info.info = format!(
                                "{} → {} [{}] Seq={} Ack={} Win={} Len={}",
                                tcp.get_source(),
                                tcp.get_destination(),
                                self.tcp_flags_to_str(tcp.get_flags()),
                                tcp.get_sequence(),
                                tcp.get_acknowledgement(),
                                tcp.get_window(),
                                tcp.payload().len()
                            );
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        packet_info.protocol = "UDP".to_string();
                        if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                            packet_info.info = format!(
                                "{} → {} Len={}",
                                udp.get_source(),
                                udp.get_destination(),
                                udp.get_length()
                            );
                        }
                    }
                    IpNextHeaderProtocols::Icmp => {
                        packet_info.protocol = "ICMP".to_string();
                        if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                            let icmp_type = match icmp.get_icmp_type() {
                                IcmpTypes::EchoReply => "Echo Reply",
                                IcmpTypes::EchoRequest => "Echo Request",
                                IcmpTypes::DestinationUnreachable => "Destination Unreachable",
                                _ => "Other ICMP",
                            };
                            packet_info.info = icmp_type.to_string();
                        }
                    }
                    _ => {
                        packet_info.protocol = format!("IPv4 Protocol {}", ipv4.get_next_level_protocol());
                    }
                }
            }
            EtherTypes::Ipv6 => {
                let ipv6 = Ipv6Packet::new(ethernet.payload())?;
                packet_info.source = ipv6.get_source().to_string();
                packet_info.destination = ipv6.get_destination().to_string();
                packet_info.protocol = "IPv6".to_string();
            }
            EtherTypes::Arp => {
                packet_info.protocol = "ARP".to_string();
            }
            _ => {
                packet_info.protocol = format!("EtherType {}", ethernet.get_ethertype());
            }
        }
        
        Some(packet_info)
    }
    
    fn tcp_flags_to_str(&self, flags: u16) -> String {
        let mut flag_str = String::new();
        if flags & 0x01 != 0 { flag_str.push('F'); } // FIN
        if flags & 0x02 != 0 { flag_str.push('S'); } // SYN
        if flags & 0x04 != 0 { flag_str.push('R'); } // RST
        if flags & 0x08 != 0 { flag_str.push('P'); } // PSH
        if flags & 0x10 != 0 { flag_str.push('A'); } // ACK
        if flags & 0x20 != 0 { flag_str.push('U'); } // URG
        if flags & 0x40 != 0 { flag_str.push('E'); } // ECE
        if flags & 0x80 != 0 { flag_str.push('C'); } // CWR
        flag_str
    }
}
