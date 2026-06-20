use tracing::{info, warn};

mod modules;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize standard logging
    tracing_subscriber::fmt::init();
    info!("ARGUS scan-engine initializing...");

    // TODO: Phase 1 Guardrail - Implement gRPC call to auth-gateway
    // to verify target IP is within the authorized engagement scope.
    let target_ip = "127.0.0.1"; 
    let is_authorized = check_authorized_scope(target_ip).await;

    if !is_authorized {
        warn!("Target {} is OUT OF SCOPE. Execution halted.", target_ip);
        return Ok(());
    }

    info!("Target authorized. Engine ready.");
    
    // Future execution logic will branch here based on the gRPC request
    
    Ok(())
}

async fn check_authorized_scope(_ip: &str) -> bool {
    // Hardcoded to true for local development until the gateway is wired
    true 
}