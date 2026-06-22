use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info};

/// Locates the active network interface for raw packet injection.
pub fn get_active_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    interfaces.into_iter().find(|iface| {
        !iface.is_loopback() && !iface.ips.is_empty() && iface.ips.iter().any(|ip| ip.is_ipv4())
    })
}

/// Initializes the raw socket and executes the requested multi-mode timing sequence.
pub async fn execute_raw_scan(
    target_ip: &str,
    target_ports: Vec<u16>,
    scan_type: &str,
    timing_mode: &str,
) {
    info!("Initializing native raw socket for {} scan...", scan_type);

    let interface = match get_active_interface() {
        Some(iface) => iface,
        None => {
            error!("Fatal: Could not locate an active network interface.");
            return;
        }
    };

    let source_ip = interface.ips.iter().find(|ip| ip.is_ipv4()).unwrap().ip();
    let source_ipv4 = match source_ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => unreachable!(),
    };
    let target_ipv4 = Ipv4Addr::from_str(target_ip).expect("Invalid IP");
    let source_mac = interface.mac.unwrap_or(MacAddr::zero());
    let target_mac = MacAddr::broadcast();

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Fatal: Unhandled channel type."),
        Err(e) => panic!("Fatal: Failed to create datalink channel: {}", e),
    };

    // THE GLOBAL LISTENER
    let listener_target = target_ipv4;
    tokio::task::spawn_blocking(move || {
        info!("Receiver online. Monitoring returning traffic...");
        loop {
            if let Ok(packet) = rx.next() {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()) {
                        if ipv4_packet.get_source() == listener_target {
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                let flags = tcp_packet.get_flags();
                                let replied_port = tcp_packet.get_source();

                                if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
                                    info!(">> PORT {} IS OPEN (SYN-ACK) <<", replied_port);
                                } else if (flags & TcpFlags::RST) != 0 {
                                    debug!("Port {} is closed (RST).", replied_port);
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Short pause to ensure the background consumer thread is fully scheduled
    sleep(Duration::from_millis(100)).await;

    info!(
        "Transmitting payloads across {} ports...",
        target_ports.len()
    );

    // Switch behavioral paths depending on the desired profile
    match timing_mode {
        "stealth" => {
            info!("Stealth protocol activated: Applying randomized mathematical jitter per target segment.");
            for (index, port) in target_ports.iter().enumerate() {
                let tcp_payload =
                    crate::modules::crafter::build_tcp_payload(source_ipv4, 54321, target_ipv4, *port, scan_type);
                let ipv4_packet = crate::modules::crafter::build_ipv4_packet(
                    source_ipv4,
                    target_ipv4,
                    &tcp_payload,
                );
                let final_frame = crate::modules::crafter::build_ethernet_frame(
                    source_mac,
                    target_mac,
                    &ipv4_packet,
                );

                if let Some(Err(e)) = tx.send_to(&final_frame, None) {
                    error!("Transmission failed on port {}: {}", port, e);
                }

                // Apply randomized sleep after each packet except the absolute last one
                if index < target_ports.len() - 1 {
                    let jitter_ms = (rand::random::<u64>() % 601) + 300; // Calculates 300ms to 900ms
                    debug!("Evasion metrics: Sleeping for {}ms...", jitter_ms);
                    sleep(Duration::from_millis(jitter_ms)).await;
                }
            }
        }
        _ => {
            // Default execution profile handles "fast"
            info!("Performance protocol activated: Executing high-throughput batching (500 segments/burst).");
            for (index, port) in target_ports.iter().enumerate() {
                let tcp_payload =
                    crate::modules::crafter::build_tcp_payload(source_ipv4, 54321, target_ipv4, *port, scan_type);
                let ipv4_packet = crate::modules::crafter::build_ipv4_packet(
                    source_ipv4,
                    target_ipv4,
                    &tcp_payload,
                );
                let final_frame = crate::modules::crafter::build_ethernet_frame(
                    source_mac,
                    target_mac,
                    &ipv4_packet,
                );

                if let Some(Err(e)) = tx.send_to(&final_frame, None) {
                    error!("Transmission failed on port {}: {}", port, e);
                }

                // Hardware throttling guardrail: Pause for 15ms every 500 packets to let ring buffers flush
                if (index + 1) % 500 == 0 && index < target_ports.len() - 1 {
                    debug!("Hardware Guardrail: Flushing network interfaces for 15ms...");
                    sleep(Duration::from_millis(15)).await;
                }
            }
        }
    }

    info!("All payloads successfully transmitted. Holding for trailing responses...");
    sleep(Duration::from_secs(3)).await;
    info!("Scan cycle complete.");
}
