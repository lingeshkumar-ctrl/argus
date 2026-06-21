use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use tracing::info;

const TCP_HEADER_LEN: usize = 20;
const IPV4_HEADER_LEN: usize = 20;
const ETHERNET_HEADER_LEN: usize = 14;

/// 1. Constructs the TCP SYN header
pub fn build_tcp_syn(
    source_ip: Ipv4Addr,
    source_port: u16,
    target_ip: Ipv4Addr,
    target_port: u16,
) -> Vec<u8> {
    let mut tcp_buffer = vec![0u8; TCP_HEADER_LEN];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

    tcp_packet.set_source(source_port);
    tcp_packet.set_destination(target_port);
    tcp_packet.set_sequence(rand::random::<u32>());
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);

    let checksum =
        pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &target_ip);
    tcp_packet.set_checksum(checksum);

    info!("Crafted 20-byte TCP SYN segment.");
    tcp_buffer
}

/// 2. Wraps the TCP segment in an IPv4 Header
pub fn build_ipv4_packet(source_ip: Ipv4Addr, target_ip: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut ipv4_buffer = vec![0u8; IPV4_HEADER_LEN + payload.len()];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5); // 5 words = 20 bytes
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + payload.len()) as u16);
    ipv4_packet.set_ttl(64); // Time-to-Live
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(target_ip);
    ipv4_packet.set_payload(payload);

    let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);

    info!("Wrapped payload in IPv4 Header.");
    ipv4_buffer
}

/// 3. Wraps the IPv4 packet in an Ethernet Frame
pub fn build_ethernet_frame(source_mac: MacAddr, target_mac: MacAddr, payload: &[u8]) -> Vec<u8> {
    let mut eth_buffer = vec![0u8; ETHERNET_HEADER_LEN + payload.len()];
    let mut eth_frame = MutableEthernetPacket::new(&mut eth_buffer).unwrap();

    eth_frame.set_source(source_mac);
    eth_frame.set_destination(target_mac);
    eth_frame.set_ethertype(EtherTypes::Ipv4);
    eth_frame.set_payload(payload);

    info!(
        "Wrapped IPv4 packet in Ethernet Frame. Total size: {} bytes.",
        eth_buffer.len()
    );
    eth_buffer
}
