use dns_parser::Packet;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
struct DnsTurnaround {
    name: String,
    records: Vec<String>,
    latency_ns: i64,
}

lazy_static! {
    static ref DNS_PACKETS: Mutex<HashMap<i32, DnsTurnaround>> = Mutex::new(HashMap::new());
}

// import some WASM runtime functions from the module `env`
#[link(wasm_import_module = "env")]
extern "C" {
    fn _debug(s: &str) -> i32;
    fn clock_ns() -> i64;
}

#[no_mangle]
pub static mut SOURCE: [i8; 20] = [0; 20];
#[no_mangle]
pub static mut DESTINATION: [i8; 20] = [0; 20];
#[no_mangle]
pub static mut DNS_PACKET: [u8; 512] = [0; 512];

// source: &str, destination: &str
#[no_mangle]
extern "C" fn dns_query(id: i32) {
    unsafe {
        let timestamp = clock_ns();
        let source = CString::from_raw(SOURCE.as_mut_ptr());
        let destination = CString::from_raw(DESTINATION.as_mut_ptr());

        let mut s = format!(
            "wasm3: {}: dns_query {} -> source ip: {}, destination ip: {}",
            clock_ns(),
            id,
            source.to_string_lossy(),
            destination.to_string_lossy(),
        );

        _debug(&s);

        match Packet::parse(&DNS_PACKET[..]) {
            Ok(dns) => {
                s = format!("wasm3: {:?}", dns);
                _debug(&s);

                let turnaround = DnsTurnaround {
                    name: dns.questions[0].qname.to_string(),
                    records: Vec::new(),
                    latency_ns: timestamp,
                };
                DNS_PACKETS.lock().unwrap().insert(id, turnaround);
            }
            Err(e) => {
                s = format!("wasm3: error: {:?}", e);
                _debug(&s);
            }
        }
    }
}

#[no_mangle]
// source: &str, destination: &str
extern "C" fn dns_response(id: i32) {
    unsafe {
        let timestamp = clock_ns();
        let source = CString::from_raw(SOURCE.as_mut_ptr());
        let destination = CString::from_raw(DESTINATION.as_mut_ptr());

        let mut s = format!(
            "wasm3: {}, dns_response {} -> source ip: {}, destination ip: {}",
            clock_ns(),
            id,
            source.to_string_lossy(),
            destination.to_string_lossy(),
        );

        _debug(&s);

        match Packet::parse(&DNS_PACKET[..]) {
            Ok(dns) => {
                s = format!("wasm3: {:?}", dns);
                _debug(&s);

                match DNS_PACKETS.lock().unwrap().get_mut(&id) {
                    Some(t) => {
                        *t = DnsTurnaround {
                            name: dns.questions[0].qname.to_string(),
                            records: Vec::new(),
                            latency_ns: timestamp - t.latency_ns,
                        };
                    }
                    None => {
                        _debug("wasm3: can't find entry in hashmap");
                    }
                }
            }
            Err(e) => {
                s = format!("wasm3: error: {:?}", e);
                _debug(&s);
            }
        }

        // print out the answers in JSON
        for (k, v) in &*DNS_PACKETS.lock().unwrap() {
            s = format!("wasm3: entry: {} -> {:?}", k, serde_json::to_string(&v));
            _debug(&s);
        }
    }
}

fn main() {
    // unsafe {
    //     _debug("wasm3: hello world");
    // }
}
