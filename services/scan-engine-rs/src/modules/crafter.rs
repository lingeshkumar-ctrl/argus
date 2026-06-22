use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use tracing::debug;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const ETHERNET_HEADER_LEN: usize = 14;

/// Dynamically builds a TCP segment based on the requested scan type
pub fn build_tcp_payload(
    source_ip: Ipv4Addr,
    source_port: u16,
    target_ip: Ipv4Addr,
    target_port: u16,
    scan_type: &str,
) -> Vec<u8> {
    let mut tcp_buffer = vec![0u8; TCP_HEADER_LEN];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(target_port);
    tcp_packet.set_sequence(rand::random::<u32>());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_reserved(0);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0);

    // The advanced stealth bit-flipping logic
    match scan_type.to_lowercase().as_str() {
        "fin" => {
            debug!("Crafting FIN segment...");
            tcp_packet.set_flags(TcpFlags::FIN);
        }
        "null" => {
            debug!("Crafting NULL segment...");
            tcp_packet.set_flags(0);
        }
        "xmas" => {
            debug!("Crafting XMAS segment...");
            tcp_packet.set_flags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
        }
        _ => {
            debug!("Crafting SYN segment...");
            tcp_packet.set_flags(TcpFlags::SYN);
        }
    }

    let checksum =
        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &target_ip);
    tcp_packet.set_checksum(checksum);

    tcp_packet.packet().to_vec()
}

pub fn build_ipv4_packet(source_ip: Ipv4Addr, target_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut ipv4_buffer = vec![0u8; IPV4_HEADER_LEN + payload.len()];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_dscp(0);
    ipv4_packet.set_ecn(0);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + payload.len()) as u16);
    ipv4_packet.set_identification(rand::random::<u16>());
    ipv4_packet.set_flags(Ipv4Flags::DontFragment);
    ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(target_ip);

    let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);
    ipv4_packet.set_payload(payload);

    debug!("Wrapped payload in IPv4 Header.");
    ipv4_packet.packet().to_vec()
}

pub fn build_ethernet_frame(source_mac: MacAddr, target_mac: MacAddr, payload: &[u8]) -> Vec<u8> {
    // 1. Calculate the size BEFORE we borrow anything
    let total_size = ETHERNET_HEADER_LEN + payload.len();
    let mut eth_buffer = vec![0u8; total_size];

    // 2. Hand exclusive mutable control to eth_packet
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_buffer).unwrap();

    eth_packet.set_source(source_mac);
    eth_packet.set_destination(target_mac);
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    eth_packet.set_payload(payload);

    // 3. Print the pre-calculated integer instead of borrowing the buffer again
    debug!(
        "Wrapped IPv4 packet in Ethernet Frame. Total size: {} bytes.",
        total_size
    );
    eth_packet.packet().to_vec()
}
