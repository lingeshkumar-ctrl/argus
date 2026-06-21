use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::util::MacAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tracing::{error, info};

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

/// Initializes the raw socket and prepares for TCP flag manipulation.
pub async fn execute_raw_scan(target_ip: &str, scan_type: &str) {
    info!(
        "Initializing native raw socket for {} scan against {}",
        scan_type, target_ip
    );

    let interface = match get_active_interface() {
        Some(iface) => iface,
        None => {
            error!("Fatal: Could not locate an active, routable network interface.");
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
    // Temporarily broadcast the frame so the local switch routes it
    let target_mac = MacAddr::broadcast();

    // 1. Craft the Nested Payloads
    let tcp_payload = crate::modules::crafter::build_tcp_syn(source_ipv4, 54321, target_ipv4, 80);
    let ipv4_packet =
        crate::modules::crafter::build_ipv4_packet(source_ipv4, target_ipv4, &tcp_payload);
    let final_frame =
        crate::modules::crafter::build_ethernet_frame(source_mac, target_mac, &ipv4_packet);

    // 2. Open the physical transmission channel
    let (mut tx, _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Fatal: Unhandled channel type. Expected Ethernet."),
        Err(e) => panic!("Fatal: Failed to create datalink channel: {}", e),
    };

    // 3. FIRE THE PAYLOAD
    info!("Transmitting payload onto the wire...");
    match tx.send_to(&final_frame, None) {
        Some(Ok(_)) => info!("SUCCESS: SYN Packet physically injected into the network."),
        Some(Err(e)) => error!("Failed to send packet: {}", e),
        None => error!("Failed to send packet: Channel closed."),
    }
}
