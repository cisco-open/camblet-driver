use dns_parser::Packet;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize)]
struct DnsTurnaround {
    name: String,
    records: Vec<String>,
    latency_ns: i64,
    client: String,
    server: String,
    response_code: u8,
}

lazy_static! {
    static ref DNS_PACKETS: Mutex<HashMap<i32, DnsTurnaround>> = Mutex::new(HashMap::new());
}

/// Allocate memory into the module's linear memory
/// and return the offset to the start of the block.
#[no_mangle]
pub fn malloc(len: usize) -> *mut u8 {
    // create a new mutable buffer with capacity `len`
    let mut buf = Vec::with_capacity(len);
    // take a mutable pointer to the buffer
    let ptr = buf.as_mut_ptr();
    // take ownership of the memory block and
    // ensure that its destructor is not
    // called when the object goes out of scope
    // at the end of the function
    std::mem::forget(buf);
    // return the pointer so the runtime
    // can write data at this offset
    return ptr;
}

#[no_mangle]
pub unsafe fn free(ptr: *mut u8, size: usize) {
    let data = Vec::from_raw_parts(ptr, size, size);

    std::mem::drop(data);
}

// import some WASM runtime functions from the module `env`
#[link(wasm_import_module = "env")]
extern "C" {
    fn submit_metric(metric: &str) -> i32;
    fn _debug(s: &str) -> i32;
    fn clock_ns() -> i64;
}

// #[no_mangle]
// pub static mut SOURCE: [i8; 20] = [0; 20];
// #[no_mangle]
// pub static mut DESTINATION: [i8; 20] = [0; 20];
// #[no_mangle]
// pub static mut DNS_PACKET: [u8; 512] = [0; 512];

#[no_mangle]
extern "C" fn dns_query(id: i32, source: u32, destination: u32, dns_packet: *const [u8]) {
    unsafe {
        let timestamp = clock_ns();
        // let source = CString::from_raw(SOURCE.as_mut_ptr());
        // let destination = CString::from_raw(DESTINATION.as_mut_ptr());

        let mut s = format!(
            "wasm3: {}: dns_query {} -> source ip: {}, destination ip: {}",
            timestamp,
            id,
            Ipv4Addr::from(source),
            Ipv4Addr::from(destination),
            // source.to_string_lossy(),
            // destination.to_string_lossy(),
        );

        _debug(&s);

        match Packet::parse(&*dns_packet) {
            Ok(dns) => {
                s = format!("wasm3: {:?}", dns);
                _debug(&s);

                let turnaround = DnsTurnaround {
                    name: dns.questions[0].qname.to_string(),
                    records: Vec::new(),
                    latency_ns: timestamp,
                    client: Ipv4Addr::from(source).to_string(),
                    server: Ipv4Addr::from(destination).to_string(),
                    response_code: dns.header.response_code.into(),
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
extern "C" fn dns_response(id: i32, source: u32, destination: u32, dns_packet: *const [u8]) {
    unsafe {
        let timestamp = clock_ns();
        // let source = CString::from_raw(SOURCE.as_mut_ptr());
        // let destination = CString::from_raw(DESTINATION.as_mut_ptr());

        let mut s = format!(
            "wasm3: {}, dns_response {} -> source ip: {}, destination ip: {}",
            timestamp,
            id,
            Ipv4Addr::from(source),
            Ipv4Addr::from(destination),
            // source.to_string_lossy(),
            // destination.to_string_lossy(),
        );

        _debug(&s);

        match Packet::parse(&*dns_packet) {
            Ok(dns) => {
                s = format!("wasm3: {:?}", dns);
                _debug(&s);

                let mut packets = DNS_PACKETS.lock().unwrap();

                match packets.get_mut(&id) {
                    Some(t) => {
                        t.records = dns
                            .answers
                            .into_iter()
                            .map(|a| format!("{:?}", a.data))
                            .collect();
                        t.latency_ns = timestamp - t.latency_ns;
                        t.response_code = dns.header.response_code.into();
                        let json = serde_json::to_string(&t).unwrap() + "\n";
                        submit_metric(&json);                
                        packets.remove(&id);
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
        for (_, v) in DNS_PACKETS.lock().unwrap().iter_mut().next() {
            let is_timeouted = (timestamp - v.latency_ns) > 1000000000;
            if is_timeouted {
                v.response_code = 255; 
                let json = serde_json::to_string(&v).unwrap() + "\n";
                submit_metric(&json);        
            }
        }

        _debug(&format!("wasm3: dns packets in memory: {:?}", DNS_PACKETS.lock().unwrap().len()));

        DNS_PACKETS.lock().unwrap().retain(|_, v: &mut DnsTurnaround| ((timestamp - v.latency_ns) < 1000000000));
    }
}


fn main() {
    // unsafe {
    //     _debug("wasm3: hello world");
    // }
}
