use clap::Parser;
use tracing::info;

pub mod modules;

/// ARGUS Scan Engine - Raw Network Injection Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The target IPv4 address (e.g., 192.168.1.1)
    #[arg(short = 't', long)]
    target: String,

    /// The target port or range (e.g., "80" or "1-1000")
    #[arg(short = 'p', long)]
    ports: String,

    /// The type of stealth scan to execute (syn, fin, null, xmas)
    #[arg(short = 's', long, default_value_t = String::from("syn"))]
    scan_type: String,

    /// Timing profile: "fast" (batch-burst) or "stealth" (per-packet random jitter)
    #[arg(short = 'T', long, default_value_t = String::from("fast"))]
    timing: String,
}

/// Expands a string string like "80-85" into a numeric vector: [80, 81, 82, 83, 84, 85]
fn parse_ports(port_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    if port_str.contains('-') {
        let parts: Vec<&str> = port_str.split('-').collect();
        if parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                for p in start..=end {
                    ports.push(p);
                }
            }
        }
    } else if let Ok(p) = port_str.parse::<u16>() {
        ports.push(p);
    }
    ports
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let target_ports = parse_ports(&args.ports);
    if target_ports.is_empty() {
        tracing::error!("Fatal: No valid ports provided. Use --ports 80 or --ports 1-1000.");
        return;
    }

    info!("Booting ARGUS Engine...");
    info!(
        "Target Acquired: {} | Ports to Scan: {}",
        args.target,
        target_ports.len()
    );
    info!(
        "Scan Profile: [{}] | Timing Architecture: [{}]",
        args.scan_type.to_uppercase(),
        args.timing.to_uppercase()
    );

    modules::native_socket::execute_raw_scan(
        &args.target,
        target_ports,
        &args.scan_type,
        &args.timing,
    )
    .await;
}
