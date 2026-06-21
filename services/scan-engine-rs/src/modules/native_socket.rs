use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::util::MacAddr;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags};
use tracing::{error, info, warn};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tokio::time::{timeout, Duration};

/// Locates the active network interface for raw packet injection.
pub fn get_active_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    for iface in &interfaces {
        tracing::debug!("Detected adapter: {} | IPs: {:?}", iface.name, iface.ips);
    }
    interfaces.into_iter().find(|iface| {
        !iface.is_loopback() && !iface.ips.is_empty() && iface.ips.iter().any(|ip| ip.is_ipv4())
    })
}

/// Initializes the raw socket and executes a two-way asynchronous scan.
pub async fn execute_raw_scan(target_ip: &str, scan_type: &str) {
    info!("Initializing native raw socket for {} scan against {}", scan_type, target_ip);

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

    // 1. Craft the Nested Payload
    let target_port = 80;
    let tcp_payload = crate::modules::crafter::build_tcp_syn(source_ipv4, 54321, target_ipv4, target_port);
    let ipv4_packet = crate::modules::crafter::build_ipv4_packet(source_ipv4, target_ipv4, &tcp_payload);
    let final_frame = crate::modules::crafter::build_ethernet_frame(source_mac, target_mac, &ipv4_packet);

    // 2. Open the physical transmission channel (Extract BOTH tx and rx)
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Fatal: Unhandled channel type."),
        Err(e) => panic!("Fatal: Failed to create datalink channel: {}", e),
    };

    // 3. SPINNER: THE ASYNCHRONOUS RECEIVER
    let listener_target = target_ipv4;
    let listener_handle = tokio::task::spawn_blocking(move || {
        info!("Receiver online. Listening for target responses...");
        
        loop {
            match rx.next() {
                Ok(packet) => {
                    let eth_packet = EthernetPacket::new(packet).unwrap();
                    if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                        if let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()) {
                            
                            // Ensure the packet is coming BACK from our target
                            if ipv4_packet.get_source() == listener_target {
                                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                    let flags = tcp_packet.get_flags();
                                    
                                    // Evaluate TCP Flags
                                    if (flags & TcpFlags::SYN) != 0 && (flags & TcpFlags::ACK) != 0 {
                                        info!(">> PORT {} IS OPEN (Received SYN-ACK) <<", tcp_packet.get_source());
                                        return; 
                                    } else if (flags & TcpFlags::RST) != 0 {
                                        warn!(">> PORT {} IS CLOSED (Received RST) <<", tcp_packet.get_source());
                                        return;
                                    }
                                }
                            }
                        }
                    }
                },
                Err(e) => {
                    error!("Receiver fault: {}", e);
                    return;
                }
            }
        }
    });

    // Give the listener 50ms to boot up before we fire the payload
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. FIRE THE PAYLOAD
    info!("Transmitting SYN payload...");
    match tx.send_to(&final_frame, None) {
        Some(Ok(_)) => info!("SUCCESS: SYN injected. Awaiting response..."),
        Some(Err(e)) => error!("Failed to send packet: {}", e),
        None => error!("Failed to send packet: Channel closed."),
    }

    // 5. WAIT FOR LISTENER WITH TIMEOUT GUARDRAIL
    match timeout(Duration::from_secs(3), listener_handle).await {
        Ok(_) => info!("Scan cycle complete."),
        Err(_) => warn!(">> PORT {} IS FILTERED (Timeout: No response received) <<", target_port),
    }
}