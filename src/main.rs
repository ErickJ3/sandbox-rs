use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde_json::json;

async fn execute_python_code(req_body: String) -> impl Responder {
    Python::with_gil(|py| {
        let sys = PyModule::import(py, "sys").unwrap();
        let io = PyModule::import(py, "io").unwrap();

        let stdout = io.getattr("StringIO").unwrap().call0().unwrap();
        sys.setattr("stdout", stdout).unwrap();

        let lines: Vec<&str> = req_body.lines().collect();
        let mut last_output = String::new();

        for (i, line) in lines.iter().enumerate() {
            let is_last_line = i == lines.len() - 1;

            match py.eval(line, None, None) {
                Ok(val) => {
                    if is_last_line {
                        last_output = val.str().unwrap().to_string();
                    }
                }
                Err(_) => {
                    py.run(line, None, None).unwrap();
                }
            }
        }

        match py.run(&req_body, None, None) {
            Ok(_) => {
                let stdout = sys.getattr("stdout").unwrap();
                sys.setattr("stdout", sys.getattr("stderr").unwrap())
                    .unwrap();
                let print_output = stdout
                    .call_method0("getvalue")
                    .unwrap()
                    .extract::<String>()
                    .unwrap();

                let output = if !print_output.is_empty() {
                    print_output
                } else {
                    last_output
                };

                let json_output = json!({ "result": output });
                HttpResponse::Ok().json(json_output)
            }
            Err(e) => {
                e.print(py);
                HttpResponse::InternalServerError().body("Error executing Python code")
            }
        }
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pyo3::prepare_freethreaded_python();
    println!("server on in: 8080");
    HttpServer::new(|| App::new().route("/execute", web::post().to(execute_python_code)))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
