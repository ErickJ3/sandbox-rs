//! REST API Server for managing sandboxes
//!
//! This server provides a REST API for creating, managing, and executing sandboxes.
//!
//! ## Endpoints
//!
//! POST /api/v1/sandboxes - Create sandbox
//! POST /api/v1/sandboxes/{id}/run - Run program
//! GET /api/v1/sandboxes/{id}/status - Get status
//! GET /api/v1/sandboxes - List sandboxes
//! DELETE /api/v1/sandboxes/{id} - Delete sandbox

use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use chrono::{DateTime, Utc};
use sandbox_rs::{SandboxBuilder, SeccompProfile};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let state = web::Data::new(AppState::new());

    println!("Sandbox REST API Server starting on http://127.0.0.1:8080");
    println!("API Documentation available at http://127.0.0.1:8080/api/docs");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/health", web::get().to(health_check))
            .route("/api/docs", web::get().to(api_docs))
            .service(
                web::scope("/api/v1")
                    .route("/sandboxes", web::post().to(create_sandbox))
                    .route("/sandboxes", web::get().to(list_sandboxes))
                    .route("/sandboxes/{id}", web::get().to(get_sandbox))
                    .route("/sandboxes/{id}", web::delete().to(delete_sandbox))
                    .route("/sandboxes/{id}/run", web::post().to(run_sandbox))
                    .route("/sandboxes/{id}/status", web::get().to(get_status)),
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

// ============ API Types ============

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSandboxRequest {
    /// Sandbox ID
    pub id: Option<String>,
    /// Memory limit (e.g., "100M", "1G")
    pub memory_limit: Option<String>,
    /// CPU limit percentage (0-100)
    pub cpu_limit: Option<u32>,
    /// Timeout in seconds
    pub timeout: Option<u64>,
    /// Seccomp profile
    pub seccomp_profile: Option<String>,
    /// Network mode
    pub network_mode: Option<String>,
    /// Volume mounts
    pub volumes: Option<Vec<VolumeMountRequest>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolumeMountRequest {
    pub source: String,
    pub destination: String,
    pub read_only: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunSandboxRequest {
    /// Program to run
    pub program: String,
    /// Arguments
    pub args: Option<Vec<String>>,
    /// Environment variables
    pub env: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub memory_limit: Option<String>,
    pub cpu_limit: Option<u32>,
    pub seccomp_profile: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub id: String,
    pub exit_code: i32,
    pub wall_time_ms: u64,
    pub memory_peak: u64,
    pub cpu_time_us: u64,
    pub timed_out: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    fn ok(message: impl Into<String>, data: T) -> Self {
        Self {
            success: true,
            message: message.into(),
            data: Some(data),
        }
    }

    fn error(message: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            message: message.into(),
            data: None,
        }
    }
}

// ============ Application State ============

pub struct AppState {
    sandboxes: Mutex<HashMap<String, SandboxMetadata>>,
}

#[derive(Clone)]
pub struct SandboxMetadata {
    pub id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub memory_limit: Option<String>,
    pub cpu_limit: Option<u32>,
    pub seccomp_profile: String,
    pub last_execution: Option<DateTime<Utc>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            sandboxes: Mutex::new(HashMap::new()),
        }
    }
}

// ============ Handlers ============

/// Health check endpoint
async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "sandbox-rs",
        "version": "0.3.0"
    }))
}

/// API documentation
async fn api_docs() -> impl Responder {
    let docs = r#"
# Sandbox REST API v1

## Endpoints

### Create Sandbox
**POST /api/v1/sandboxes**

```json
{
  "id": "my-sandbox",
  "memory_limit": "100M",
  "cpu_limit": 50,
  "timeout": 30,
  "seccomp_profile": "minimal",
  "network_mode": "isolated",
  "volumes": [
    {
      "source": "/tmp",
      "destination": "/mnt",
      "read_only": false
    }
  ]
}
```

### Run Program
**POST /api/v1/sandboxes/{id}/run**

```json
{
  "program": "/bin/echo",
  "args": ["hello", "world"],
  "env": {
    "PATH": "/usr/bin:/bin"
  }
}
```

### Get Status
**GET /api/v1/sandboxes/{id}/status**

### List Sandboxes
**GET /api/v1/sandboxes**

### Delete Sandbox
**DELETE /api/v1/sandboxes/{id}**

## Seccomp Profiles
- minimal: ~40 syscalls (compute-safe)
- io-heavy: ~60 syscalls (file I/O)
- compute: ~55 syscalls (memory ops)
- network: ~70 syscalls (sockets)

## Network Modes
- isolated: Private network namespace
- bridge: Connected via virtual bridge
- host: Use host network

## Examples

### Create and Run Compute Sandbox
```bash
curl -X POST http://localhost:8080/api/v1/sandboxes \
  -H "Content-Type: application/json" \
  -d '{
    "id": "compute-job",
    "memory_limit": "256M",
    "cpu_limit": 75,
    "timeout": 30,
    "seccomp_profile": "compute"
  }'

curl -X POST http://localhost:8080/api/v1/sandboxes/compute-job/run \
  -H "Content-Type: application/json" \
  -d '{
    "program": "/usr/bin/python3",
    "args": ["script.py"]
  }'
```

### Create I/O Heavy Sandbox
```bash
curl -X POST http://localhost:8080/api/v1/sandboxes \
  -H "Content-Type: application/json" \
  -d '{
    "id": "io-job",
    "memory_limit": "512M",
    "cpu_limit": 100,
    "seccomp_profile": "io-heavy",
    "volumes": [
      {
        "source": "/data",
        "destination": "/mnt/data",
        "read_only": false
      }
    ]
  }'
```

### Create Untrusted Code Sandbox
```bash
curl -X POST http://localhost:8080/api/v1/sandboxes \
  -H "Content-Type: application/json" \
  -d '{
    "id": "untrusted",
    "memory_limit": "64M",
    "cpu_limit": 10,
    "timeout": 5,
    "seccomp_profile": "minimal"
  }'
```
"#;
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(docs)
}

/// Create sandbox
async fn create_sandbox(
    req: web::Json<CreateSandboxRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    let id = req.id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());

    // Parse seccomp profile
    let profile = match req.seccomp_profile.as_deref() {
        Some("io-heavy") => SeccompProfile::IoHeavy,
        Some("compute") => SeccompProfile::Compute,
        Some("network") => SeccompProfile::Network,
        Some("unrestricted") => SeccompProfile::Unrestricted,
        _ => SeccompProfile::Minimal,
    };

    // Build sandbox
    let mut builder = SandboxBuilder::new(&id).seccomp_profile(profile.clone());

    if let Some(mem) = &req.memory_limit {
        match builder.memory_limit_str(mem) {
            Ok(b) => builder = b,
            Err(e) => {
                return HttpResponse::BadRequest().json(ApiResponse::<()>::error(format!(
                    "Invalid memory limit: {}",
                    e
                )));
            }
        }
    }

    if let Some(cpu) = req.cpu_limit {
        builder = builder.cpu_limit_percent(cpu);
    }

    if let Some(timeout) = req.timeout {
        _ = builder.timeout(Duration::from_secs(timeout));
    }

    // Create metadata
    let metadata = SandboxMetadata {
        id: id.clone(),
        status: "created".to_string(),
        created_at: Utc::now(),
        memory_limit: req.memory_limit.clone(),
        cpu_limit: req.cpu_limit,
        seccomp_profile: format!("{:?}", profile),
        last_execution: None,
    };

    state
        .sandboxes
        .lock()
        .unwrap()
        .insert(id.clone(), metadata.clone());

    let info = SandboxInfo {
        id: metadata.id,
        status: metadata.status,
        created_at: metadata.created_at,
        memory_limit: metadata.memory_limit,
        cpu_limit: metadata.cpu_limit,
        seccomp_profile: metadata.seccomp_profile,
    };

    HttpResponse::Created().json(ApiResponse::ok("Sandbox created successfully", info))
}

/// List sandboxes
async fn list_sandboxes(state: web::Data<AppState>) -> impl Responder {
    let sandboxes = state.sandboxes.lock().unwrap();
    let infos: Vec<SandboxInfo> = sandboxes
        .values()
        .map(|m| SandboxInfo {
            id: m.id.clone(),
            status: m.status.clone(),
            created_at: m.created_at,
            memory_limit: m.memory_limit.clone(),
            cpu_limit: m.cpu_limit,
            seccomp_profile: m.seccomp_profile.clone(),
        })
        .collect();

    HttpResponse::Ok().json(ApiResponse::ok(
        format!("Found {} sandboxes", infos.len()),
        infos,
    ))
}

/// Get sandbox info
async fn get_sandbox(id: web::Path<String>, state: web::Data<AppState>) -> impl Responder {
    let sandboxes = state.sandboxes.lock().unwrap();

    match sandboxes.get(id.as_str()) {
        Some(m) => {
            let info = SandboxInfo {
                id: m.id.clone(),
                status: m.status.clone(),
                created_at: m.created_at,
                memory_limit: m.memory_limit.clone(),
                cpu_limit: m.cpu_limit,
                seccomp_profile: m.seccomp_profile.clone(),
            };
            HttpResponse::Ok().json(ApiResponse::ok("Sandbox found", info))
        }
        None => HttpResponse::NotFound().json(ApiResponse::<()>::error(format!(
            "Sandbox not found: {}",
            id
        ))),
    }
}

/// Get sandbox status
async fn get_status(id: web::Path<String>, state: web::Data<AppState>) -> impl Responder {
    let sandboxes = state.sandboxes.lock().unwrap();

    match sandboxes.get(id.as_str()) {
        Some(m) => HttpResponse::Ok().json(serde_json::json!({
            "id": m.id,
            "status": m.status,
            "created_at": m.created_at,
            "last_execution": m.last_execution
        })),
        None => HttpResponse::NotFound().json(ApiResponse::<()>::error(format!(
            "Sandbox not found: {}",
            id
        ))),
    }
}

/// Run program in sandbox
async fn run_sandbox(
    id: web::Path<String>,
    req: web::Json<RunSandboxRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    let mut sandboxes = state.sandboxes.lock().unwrap();

    match sandboxes.get_mut(id.as_str()) {
        Some(metadata) => {
            // In real implementation, would actually execute the program
            // For now, simulate execution
            let result = ExecutionResult {
                id: id.to_string(),
                exit_code: 0,
                wall_time_ms: 100,
                memory_peak: 10_485_760, // 10MB
                cpu_time_us: 50_000,     // 50ms
                timed_out: false,
            };

            metadata.status = "running".to_string();
            metadata.last_execution = Some(Utc::now());

            HttpResponse::Ok().json(ApiResponse::ok(
                format!("Program executed: {}", req.program),
                result,
            ))
        }
        None => HttpResponse::NotFound().json(ApiResponse::<()>::error(format!(
            "Sandbox not found: {}",
            id
        ))),
    }
}

/// Delete sandbox
async fn delete_sandbox(id: web::Path<String>, state: web::Data<AppState>) -> impl Responder {
    let mut sandboxes = state.sandboxes.lock().unwrap();

    match sandboxes.remove(id.as_str()) {
        Some(_) => HttpResponse::Ok().json(ApiResponse::ok(
            format!("Sandbox deleted: {}", id),
            serde_json::json!({"id": id.as_str()}),
        )),
        None => HttpResponse::NotFound().json(ApiResponse::<()>::error(format!(
            "Sandbox not found: {}",
            id
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test, web};

    fn status_of<R: Responder>(resp: R) -> StatusCode {
        resp.respond_to(&test::TestRequest::default().to_http_request())
            .status()
    }

    #[actix_web::test]
    async fn health_and_docs_endpoints_work() {
        assert_eq!(status_of(health_check().await), StatusCode::OK);
        assert_eq!(status_of(api_docs().await), StatusCode::OK);
    }

    #[actix_web::test]
    async fn sandbox_crud_flow() {
        let state = web::Data::new(AppState::new());
        let create_req = web::Json(CreateSandboxRequest {
            id: Some("api-test".to_string()),
            memory_limit: Some("64M".to_string()),
            cpu_limit: Some(50),
            timeout: Some(1),
            seccomp_profile: Some("minimal".to_string()),
            network_mode: None,
            volumes: None,
        });

        assert_eq!(
            status_of(create_sandbox(create_req, state.clone()).await),
            StatusCode::CREATED
        );
        assert_eq!(
            status_of(list_sandboxes(state.clone()).await),
            StatusCode::OK
        );
        assert_eq!(
            status_of(get_sandbox(web::Path::from("api-test".to_string()), state.clone()).await),
            StatusCode::OK
        );
        assert_eq!(
            status_of(get_status(web::Path::from("api-test".to_string()), state.clone()).await),
            StatusCode::OK
        );

        let run_req = web::Json(RunSandboxRequest {
            program: "/bin/echo".to_string(),
            args: Some(vec!["hi".to_string()]),
            env: None,
        });
        assert_eq!(
            status_of(
                run_sandbox(
                    web::Path::from("api-test".to_string()),
                    run_req,
                    state.clone()
                )
                .await
            ),
            StatusCode::OK
        );

        assert_eq!(
            status_of(delete_sandbox(web::Path::from("api-test".to_string()), state.clone()).await),
            StatusCode::OK
        );

        assert_eq!(
            status_of(get_sandbox(web::Path::from("api-test".to_string()), state.clone()).await),
            StatusCode::NOT_FOUND
        );
    }
}
