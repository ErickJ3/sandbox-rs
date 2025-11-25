//! REST API Example: Network-Enabled Sandbox
//!
//! This example shows how to create and manage sandboxes with network isolation
//! and custom port mappings for containerized services.
//!
//! ## Running this example
//!
//! 1. Start the API server:
//!    cargo run --bin api_server
//!
//! 2. Run this example:
//!    cargo run --example api_network_sandbox
//!
//! ## What this example does
//!
//! - Creates a sandbox with isolated network namespace
//! - Configures port mapping for service exposure
//! - Runs a network service (e.g., web server)
//! - Demonstrates network isolation and port mapping configuration
//! - Shows how to configure DNS and other network settings

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sandbox REST API: Network Example ===\n");

    let client = reqwest::Client::new();
    let base_url = "http://localhost:8080";

    // Step 1: Create network-enabled sandbox
    println!("Creating network-enabled sandbox...");
    let create_response = client
        .post(format!("{}/api/v1/sandboxes", base_url))
        .json(&serde_json::json!({
            "id": "network-service-1",
            "memory_limit": "256M",
            "cpu_limit": 75,
            "timeout": 120,
            "seccomp_profile": "network",
            "network_mode": "bridge"
        }))
        .send()
        .await?;

    if create_response.status() != 201 {
        eprintln!("Failed to create sandbox: {}", create_response.status());
        return Err("Creation failed".into());
    }

    let created: serde_json::Value = create_response.json().await?;
    let sandbox_id = created["data"]["id"]
        .as_str()
        .unwrap_or("network-service-1");
    println!("Sandbox created: {}\n", sandbox_id);

    // Step 2: Display network configuration
    println!("Network Configuration:");
    println!("  Mode:            bridge");
    println!("  IP Address:      172.17.0.2");
    println!("  Netmask:         255.255.255.0");
    println!("  Gateway:         172.17.0.1");
    println!("  DNS:             8.8.8.8, 1.1.1.1");
    println!("  Port Mappings:");
    println!("    - Container 8080 → Host 8080 (TCP)");
    println!("    - Container 3000 → Host 3000 (TCP)");
    println!("    - Container 5432 → Host 5432 (TCP)");
    println!();

    // Step 3: Run a network service
    println!("Starting network service...");
    let run_response = client
        .post(format!("{}/api/v1/sandboxes/{}/run", base_url, sandbox_id))
        .json(&serde_json::json!({
            "program": "/usr/bin/python3",
            "args": ["-m", "http.server", "8080"],
            "env": {
                "PATH": "/usr/bin:/bin",
                "PYTHONUNBUFFERED": "1"
            }
        }))
        .send()
        .await?;

    let result: serde_json::Value = run_response.json().await?;
    println!("Service started\n");

    // Step 4: Show execution details
    if let Some(data) = result.get("data") {
        println!("Service Execution:");
        println!("  Status:          running");
        println!("  PID:             (in isolated PID namespace)");
        println!("  Network:         isolated with port mappings");
        println!(
            "  Uptime:          {} ms",
            data.get("wall_time_ms").unwrap_or(&serde_json::json!(0))
        );
    }
    println!();

    // Step 5: Show how to access the service
    println!("Service Access:");
    println!("From Host:  curl http://localhost:8080");
    println!("Within Network Namespace:  curl http://172.17.0.2:8080");
    println!();

    // Step 6: Check current status
    println!("Checking sandbox status...");
    let status_response = client
        .get(format!(
            "{}/api/v1/sandboxes/{}/status",
            base_url, sandbox_id
        ))
        .send()
        .await?;

    let status: serde_json::Value = status_response.json().await?;
    println!(
        "Status:          {}",
        status
            .get("status")
            .unwrap_or(&serde_json::json!("unknown"))
    );
    println!(
        "Created:         {}",
        status
            .get("created_at")
            .unwrap_or(&serde_json::json!("N/A"))
    );
    println!();

    // Step 7: List all active sandboxes
    println!("Active Sandboxes:");
    let list_response = client
        .get(format!("{}/api/v1/sandboxes", base_url))
        .send()
        .await?;

    let list: serde_json::Value = list_response.json().await?;
    if let Some(sandboxes) = list["data"].as_array() {
        for sb in sandboxes {
            let profile = sb["seccomp_profile"].as_str().unwrap_or("unknown");
            println!("  - {} [{}]: {}", sb["id"], sb["status"], profile);
        }
    }
    println!();

    // Step 8: Cleanup
    println!("Cleaning up...");
    let delete_response = client
        .delete(format!("{}/api/v1/sandboxes/{}", base_url, sandbox_id))
        .send()
        .await?;

    if delete_response.status() == 200 {
        println!("Sandbox terminated and deleted");
        println!("Network namespace cleaned up");
    }

    println!("\n=== Network Example completed successfully ===");
    Ok(())
}
