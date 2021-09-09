#[macro_use]
extern crate lazy_static;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Mutex;

use actix_web::{web, HttpResponse};
use clap::Clap;
use libc::{c_char, size_t};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sev::certs::Chain;
use sev::launch::{Measurement, Policy, Start};
use sev::session::{Initialized, Session};
use sev::Build;
use uuid::Uuid;

const CMDLINE_PROLOG: &str = "reboot=k panic=-1 panic_print=0 pci=off nomodules console=hvc0 quiet rw no-kvmapf init=/bin/sh virtio_mmio.device=4K@0xd0000000:5 virtio_mmio.device=4K@0xd0001000:6 virtio_mmio.device=4K@0xd0002000:7 virtio_mmio.device=4K@0xd0003000:8 swiotlb=65536 KRUN_WORKDIR=/";
const CMDLINE_EPILOG: &str = "-- \0";

lazy_static! {
    static ref SESSIONS: Mutex<HashMap<String, SessionData>> = Mutex::new(HashMap::new());
    static ref CMDLINE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
}

struct SessionData {
    build: Build,
    session: Session<Initialized>,
}

#[derive(Serialize, Deserialize)]
struct SessionRequest {
    build: Build,
    chain: Chain,
}

#[derive(Serialize, Deserialize)]
struct SessionResponse {
    id: String,
    start: Start,
}

#[derive(Serialize, Deserialize)]
struct MeasurementRequest {
    msr: Measurement,
}

#[derive(Serialize, Deserialize)]
struct MeasurementResponse {
    secret: String,
}

async fn session(session_req: web::Json<SessionRequest>) -> HttpResponse {
    let chain: Chain = serde_json::from_str(&json!(session_req.chain).to_string()).unwrap();

    let policy = Policy::default();
    let session = Session::try_from(policy).unwrap();
    let start = session.start(chain).unwrap();

    let uuid = Uuid::new_v4().to_simple();

    println!("/session: new request with id={}", uuid);

    SESSIONS.lock().unwrap().insert(
        uuid.to_string(),
        SessionData {
            build: session_req.build,
            session,
        },
    );

    HttpResponse::Ok().json(SessionResponse {
        id: uuid.to_string(),
        start,
    })
}

#[link(name = "krunfw")]
extern "C" {
    fn krunfw_get_qboot(size: *mut size_t) -> *mut c_char;
    fn krunfw_get_initrd(size: *mut size_t) -> *mut c_char;
    fn krunfw_get_kernel(load_addr: *mut u64, size: *mut size_t) -> *mut c_char;
}

async fn attestation(param: web::Path<String>, json: web::Json<Measurement>) -> HttpResponse {
    if let Some(session_data) = SESSIONS.lock().unwrap().remove(&param.0) {
        let mut kernel_guest_addr: u64 = 0;
        let mut kernel_size: usize = 0;
        let kernel_host_addr = unsafe {
            krunfw_get_kernel(
                &mut kernel_guest_addr as *mut u64,
                &mut kernel_size as *mut usize,
            )
        };

        let mut qboot_size: usize = 0;
        let qboot_host_addr = unsafe { krunfw_get_qboot(&mut qboot_size as *mut usize) };

        let mut initrd_size: usize = 0;
        let initrd_host_addr = unsafe { krunfw_get_initrd(&mut initrd_size as *mut usize) };

        let qboot_data =
            unsafe { std::slice::from_raw_parts(qboot_host_addr as *const u8, qboot_size) };
        let kernel_data =
            unsafe { std::slice::from_raw_parts(kernel_host_addr as *const u8, kernel_size) };
        let initrd_data =
            unsafe { std::slice::from_raw_parts(initrd_host_addr as *const u8, initrd_size) };

        let mut session = session_data.session.measure().unwrap();

        session.update_data(qboot_data).unwrap();
        session.update_data(kernel_data).unwrap();
        session.update_data(initrd_data).unwrap();

        match session.verify(session_data.build, *json) {
            Err(_) => {
                println!("/attestation: verification failed for id={}", param.0);
                HttpResponse::BadRequest().body("measurement verification failed")
            }
            Ok(session) => {
                println!("/attestation: verification succeeded for id={}", param.0);
                let cmdline = CMDLINE.lock().unwrap().clone();
                let padding = vec![0; 512 - cmdline.len()];
                let data = [cmdline, padding].concat();
                let secret = session
                    .secret(sev::launch::HeaderFlags::default(), &data)
                    .unwrap();
                HttpResponse::Ok().json(secret)
            }
        }
    } else {
        println!("/attestation: no session found for id={}", param.0);
        return HttpResponse::BadRequest().body("can't find session id");
    }
}

#[derive(Clap)]
struct Opts {
    /// LUKS passphrase to be injected into the guest
    #[clap(short, long)]
    passphrase: String,
    /// Workload entry point (first binary to be executed in the guest).
    #[clap(short, long)]
    entry: String,
    /// Listening port.
    #[clap(long, default_value = "8080")]
    port: i32,
    /// Address to bind.
    #[clap(long, default_value = "0.0.0.0")]
    address: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_web::{App, HttpServer};

    let opts: Opts = Opts::parse();

    CMDLINE.lock().unwrap().extend_from_slice(
        format!(
            "{} KRUN_PASS={} KRUN_INIT={} {}",
            CMDLINE_PROLOG, opts.passphrase, opts.entry, CMDLINE_EPILOG
        )
        .as_bytes(),
    );

    HttpServer::new(|| {
        App::new()
            .service(web::resource("/session").route(web::post().to(session)))
            .service(web::resource("/attestation/{id}").route(web::post().to(attestation)))
    })
    .bind(format!("{}:{}", opts.address, opts.port))?
    .run()
    .await
}
