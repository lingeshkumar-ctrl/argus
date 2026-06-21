use tracing::{info, warn};

mod modules;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize standard logging
    tracing_subscriber::fmt::init();
    info!("ARGUS scan-engine initializing...");

    // Phase 1 Guardrail - Target authorization check
    let target_ip = "192.168.1.1"; // Changed from loopback to simulate an external target
    let is_authorized = check_authorized_scope(target_ip).await;

    if !is_authorized {
        warn!("Target {} is OUT OF SCOPE. Execution halted.", target_ip);
        return Ok(());
    }

    info!("Target authorized. Engaging engine.");

    // Execute the native raw socket scan
    modules::native_socket::execute_raw_scan(target_ip, "SYN").await;

    Ok(())
}

async fn check_authorized_scope(_ip: &str) -> bool {
    // Hardcoded to true for local development until the gRPC gateway is wired
    true
}
