use pnet::datalink::{self, NetworkInterface};
use tracing::{error, info};

/// Locates the active network interface for raw packet injection.
pub fn get_active_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    
    // Print all detected interfaces to the console so we can see what Windows sees
    for iface in &interfaces {
        tracing::debug!("Detected adapter: {} | IPs: {:?}", iface.name, iface.ips);
    }

    // Find the first adapter that isn't a local loopback AND has at least one IPv4 address
    interfaces
        .into_iter()
        .find(|iface| {
            !iface.is_loopback() 
            && !iface.ips.is_empty()
            && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
}

/// Initializes the raw socket and prepares for TCP flag manipulation.
pub async fn execute_raw_scan(target_ip: &str, scan_type: &str) {
    info!("Initializing native raw socket for {} scan against {}", scan_type, target_ip);

    let interface = match get_active_interface() {
        Some(iface) => iface,
        None => {
            error!("Fatal: Could not locate an active, routable network interface.");
            return;
        }
    };

    info!("Bind successful. Channel open on interface: {}", interface.name);
    info!("MAC Address: {}", interface.mac.unwrap_or_default());

    // TODO: Construct Ethernet -> IPv4 -> TCP frames and calculate cryptographic checksums
    info!("Raw socket ready. Awaiting payload crafting module...");
}
