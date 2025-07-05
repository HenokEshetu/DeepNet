use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, TcpFlags};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::icmp::{IcmpPacket, MutableIcmpPacket, IcmpTypes, echo_request::MutableEchoRequestPacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use std::net::Ipv4Addr;

use super::widgets::{packet_crafter::Protocol};

pub struct PacketCrafter {
    source_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    source_port: u16,
    dest_port: u16,
    protocol: Protocol,
    payload: String,
    count: u32,
    delay: u32,
}

impl PacketCrafter {
    pub fn new(
        source_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        source_port: u16,
        dest_port: u16,
        protocol: Protocol,
        payload: String,
        count: u32,
        delay: u32,
    ) -> Self {
        Self {
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            protocol,
            payload,
            count,
            delay,
        }
    }
    
    pub fn craft_and_send(&mut self) {
        let interfaces = pnet_datalink::interfaces();
        let interface = interfaces.iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .expect("No suitable interface found");

        let (mut tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unsupported channel type"),
            Err(e) => panic!("Error creating channel: {}", e),
        };
        
        for i in 0..self.count {
            let mut ethernet_buffer = [0u8; 42];
            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
            
            // Build Ethernet frame
            ethernet_packet.set_destination(interface.mac.unwrap());
            ethernet_packet.set_source(interface.mac.unwrap());
            ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);
            
            // Build IP packet
            let mut ip_buffer = [0u8; 20];
            let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
            
            ip_packet.set_version(4);
            ip_packet.set_header_length(5);
            ip_packet.set_total_length(20);
            ip_packet.set_ttl(64);
            ip_packet.set_source(self.source_ip);
            ip_packet.set_destination(self.dest_ip);
            
            // Build transport layer packet based on protocol
            match self.protocol {
                Protocol::Tcp => {
                    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                    ip_packet.set_total_length(40);
                    
                    let mut tcp_buffer = [0u8; 20];
                    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
                    
                    tcp_packet.set_source(self.source_port);
                    tcp_packet.set_destination(self.dest_port);
                    tcp_packet.set_flags(TcpFlags::SYN);
                    tcp_packet.set_sequence(12345);
                    tcp_packet.set_window(64240);
                    
                    // Calculate checksums
                    tcp_packet.set_checksum(0);
                    let checksum = pnet::packet::tcp::ipv4_checksum(
                        &tcp_packet.to_immutable(),
                        &self.source_ip,
                        &self.dest_ip,
                    );
                    tcp_packet.set_checksum(checksum);
                    
                    ip_packet.set_payload(tcp_packet.packet());
                }
                Protocol::Udp => {
                    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                    ip_packet.set_total_length(28);
                    
                    let mut udp_buffer = [0u8; 8];
                    let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
                    
                    udp_packet.set_source(self.source_port);
                    udp_packet.set_destination(self.dest_port);
                    udp_packet.set_length(8);
                    udp_packet.set_checksum(0);
                    
                    ip_packet.set_payload(udp_packet.packet());
                }
                Protocol::Icmp => {
                    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
                    ip_packet.set_total_length(28);
                    
                    let mut icmp_buffer = [0u8; 8];
                    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_buffer).unwrap();
                    
                    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
                    icmp_packet.set_identifier(1234);
                    icmp_packet.set_sequence_number(1);
                    
                    ip_packet.set_payload(icmp_packet.packet());
                }
                Protocol::Raw => {
                    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                    ip_packet.set_total_length(20 + self.payload.len() as u16);
                    ip_packet.set_payload(self.payload.as_bytes());
                }
            }
            
            // Set IP checksum
            ip_packet.set_checksum(0);
            let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
            ip_packet.set_checksum(checksum);
            
            // Combine packets
            ethernet_packet.set_payload(ip_packet.packet());
            
            // Send packet
            tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
        }
    }
}
