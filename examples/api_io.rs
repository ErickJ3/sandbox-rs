//! REST API Example: I/O Heavy Sandbox with Volumes
//!
//! This example shows how to use the REST API to create a sandbox with persistent
//! storage volumes for I/O intensive workloads like data processing and file operations.
//!
//! ## Running this example
//!
//! 1. Start the API server:
//!    cargo run --bin api_server
//!
//! 2. Create data directory:
//!    mkdir -p /tmp/sandbox-data
//!
//! 3. Run this example:
//!    cargo run --example api_io_sandbox
//!
//! ## What this example does
//!
//! - Creates a sandbox configured for I/O heavy workloads
//! - Mounts volumes for input/output data
//! - Submits a data processing job
//! - Monitors execution with higher memory and CPU limits
//! - Demonstrates volume management and cleanup

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sandbox REST API: I/O Heavy Example ===\n");

    let client = reqwest::Client::new();
    let base_url = "http://localhost:8080";

    // Step 1: Create I/O sandbox with volume mounts
    println!("Creating I/O sandbox with volume mounts...");
    let create_response = client
        .post(format!("{}/api/v1/sandboxes", base_url))
        .json(&serde_json::json!({
            "id": "io-job-1",
            "memory_limit": "512M",
            "cpu_limit": 100,
            "timeout": 60,
            "seccomp_profile": "io-heavy",
            "volumes": [
                {
                    "source": "/tmp/sandbox-data",
                    "destination": "/data",
                    "read_only": false
                },
                {
                    "source": "/tmp",
                    "destination": "/tmp",
                    "read_only": false
                }
            ]
        }))
        .send()
        .await?;

    if create_response.status() != 201 {
        eprintln!("Failed to create sandbox: {}", create_response.status());
        return Err("Creation failed".into());
    }

    let created: serde_json::Value = create_response.json().await?;
    let sandbox_id = created["data"]["id"].as_str().unwrap_or("io-job-1");
    println!("✓ Sandbox created: {}\n", sandbox_id);

    // Step 2: Get sandbox info
    println!("Sandbox configuration:");
    let info_response = client
        .get(format!("{}/api/v1/sandboxes/{}", base_url, sandbox_id))
        .send()
        .await?;

    let info: serde_json::Value = info_response.json().await?;
    if let Some(data) = info.get("data") {
        println!("ID:               {}", data["id"]);
        println!("Status:           {}", data["status"]);
        println!(
            "Memory Limit:     {}",
            data["memory_limit"].as_str().unwrap_or("N/A")
        );
        println!("CPU Limit:        {}%", data["cpu_limit"]);
        println!("Seccomp Profile:  {}", data["seccomp_profile"]);
    }
    println!();

    // Step 3: Run data processing job
    println!("Submitting data processing job...");
    let run_response = client
        .post(format!("{}/api/v1/sandboxes/{}/run", base_url, sandbox_id))
        .json(&serde_json::json!({
            "program": "/usr/bin/dd",
            "args": [
                "if=/dev/zero",
                "of=/data/output.bin",
                "bs=1M",
                "count=100"
            ],
            "env": {
                "PATH": "/usr/bin:/bin"
            }
        }))
        .send()
        .await?;

    let result: serde_json::Value = run_response.json().await?;
    println!("Job submitted\n");

    // Step 4: Display execution metrics
    if let Some(data) = result.get("data") {
        println!("Job Execution Metrics:");
        println!(
            "Wall Time:       {} ms",
            data.get("wall_time_ms").unwrap_or(&serde_json::json!(0))
        );
        println!(
            "Memory Used:     {} MB",
            data.get("memory_peak")
                .and_then(|v| v.as_u64())
                .map(|v| v / 1_000_000)
                .unwrap_or(0)
        );
        println!(
            "CPU Time:        {} us",
            data.get("cpu_time_us").unwrap_or(&serde_json::json!(0))
        );
    }
    println!();

    // Step 5: Check final status
    println!("Checking sandbox status after execution...");
    let status_response = client
        .get(format!(
            "{}/api/v1/sandboxes/{}/status",
            base_url, sandbox_id
        ))
        .send()
        .await?;

    let status: serde_json::Value = status_response.json().await?;
    println!(
        "Current Status:  {}",
        status
            .get("status")
            .unwrap_or(&serde_json::json!("unknown"))
    );
    println!(
        "Last Execution:  {}",
        status
            .get("last_execution")
            .unwrap_or(&serde_json::json!("N/A"))
    );
    println!();

    // Step 6: Clean up
    println!("Cleaning up...");
    let delete_response = client
        .delete(format!("{}/api/v1/sandboxes/{}", base_url, sandbox_id))
        .send()
        .await?;

    if delete_response.status() == 200 {
        println!("Sandbox deleted successfully");
        println!("Volumes unmounted and cleaned up");
    }

    println!("\n=== I/O Example completed successfully ===");
    Ok(())
}
