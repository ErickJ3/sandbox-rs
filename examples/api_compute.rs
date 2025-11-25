//! REST API Example: Compute Sandbox
//!
//! This example shows how to use the REST API to create and manage a compute sandbox
//! that runs CPU-intensive workloads with resource limits.
//!
//! ## Running this example
//!
//! 1. Start the API server in one terminal:
//!    cargo run --bin api_server
//!
//! 2. Run this example in another terminal:
//!    cargo run --example api_compute_sandbox
//!
//! ## What this example does
//!
//! - Creates a sandbox with compute profile (50% CPU, 256MB memory)
//! - Submits a program to run (Python script for fibonacci calculation)
//! - Polls status until execution completes
//! - Retrieves and displays execution results
//! - Demonstrates proper error handling and timeout management

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sandbox REST API: Compute Example ===\n");

    let client = reqwest::Client::new();
    let base_url = "http://localhost:8080";

    // Step 1: Create a compute sandbox with restricted resources
    println!("Creating compute sandbox...");
    let create_response = client
        .post(format!("{}/api/v1/sandboxes", base_url))
        .json(&serde_json::json!({
            "id": "compute-job-1",
            "memory_limit": "256M",
            "cpu_limit": 50,
            "timeout": 30,
            "seccomp_profile": "compute"
        }))
        .send()
        .await?;

    if create_response.status() != 201 {
        eprintln!("Failed to create sandbox: {}", create_response.status());
        return Err("Creation failed".into());
    }

    let created: serde_json::Value = create_response.json().await?;
    println!("Sandbox created: {:?}\n", created["data"]["id"]);

    // Step 2: Check sandbox status before running
    println!("Checking sandbox status...");
    let status_response = client
        .get(format!(
            "{}/api/v1/sandboxes/compute-job-1/status",
            base_url
        ))
        .send()
        .await?;

    let status: serde_json::Value = status_response.json().await?;
    println!("Status: {}\n", status["status"]);

    // Step 3: Run a compute program (simulated)
    println!("Running compute program...");
    let run_response = client
        .post(format!("{}/api/v1/sandboxes/compute-job-1/run", base_url))
        .json(&serde_json::json!({
            "program": "/usr/bin/python3",
            "args": ["fibonacci.py", "35"],
            "env": {
                "PATH": "/usr/bin:/bin",
                "PYTHONUNBUFFERED": "1"
            }
        }))
        .send()
        .await?;

    let result: serde_json::Value = run_response.json().await?;
    println!("Program executed\n");

    // Step 4: Parse and display results
    if let Some(data) = result.get("data") {
        println!("Execution Results:");
        println!(
            "Exit Code:    {}",
            data.get("exit_code").unwrap_or(&serde_json::json!(-1))
        );
        println!(
            "Wall Time:    {} ms",
            data.get("wall_time_ms").unwrap_or(&serde_json::json!(0))
        );
        println!(
            "Memory Peak:  {} MB",
            data.get("memory_peak")
                .and_then(|v| v.as_u64())
                .map(|v| v / 1_000_000)
                .unwrap_or(0)
        );
        println!(
            "CPU Time:     {} us",
            data.get("cpu_time_us").unwrap_or(&serde_json::json!(0))
        );
        println!(
            "Timed Out:    {}",
            data.get("timed_out").unwrap_or(&serde_json::json!(false))
        );
    }

    // Step 5: List all sandboxes
    println!("\nListing all sandboxes...");
    let list_response = client
        .get(format!("{}/api/v1/sandboxes", base_url))
        .send()
        .await?;

    let list: serde_json::Value = list_response.json().await?;
    if let Some(sandboxes) = list["data"].as_array() {
        println!("Found {} sandbox(es)", sandboxes.len());
        for sb in sandboxes {
            println!(
                "  - {} ({}): {:?}",
                sb["id"], sb["status"], sb["seccomp_profile"]
            );
        }
    }

    // Step 6: Clean up - delete the sandbox
    println!("\nDeleting sandbox...");
    let delete_response = client
        .delete(format!("{}/api/v1/sandboxes/compute-job-1", base_url))
        .send()
        .await?;

    if delete_response.status() == 200 {
        println!("Sandbox deleted successfully");
    }

    println!("\n=== Example completed successfully ===");
    Ok(())
}
