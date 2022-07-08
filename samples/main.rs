use dns_parser::Packet;
use serde::{Deserialize, Serialize};
use core::slice;
use std::str;
use std::net::Ipv4Addr;


#[derive(Debug, Serialize, Deserialize)]
struct DnsTurnaround {
    name: String,
    records: Vec<String>,
    latency_ns: i64,
    client: String,
    server: String,
    response_code: u8,
}

// lazy_static! {
//     static ref DNS_PACKETS: Mutex<HashMap<i16, DnsTurnaround>> = Mutex::new(HashMap::new());
// }

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
    // TODO uncomment this function if the RawFunction multi value return gets supported on wasm3(baluchicken)
    // fn table_get(id: i32) -> (i32, i32);
    fn table_get(id: i32) -> i64;
    // TODO uncomment this function if the RawFunction multi value return gets supported on wasm3(baluchicken)
    // fn table_keys() -> (i32, i32);
    fn table_keys() -> i64;
    fn table_add(key: i32, value_ptr: i32, value_lenght: i32);
    fn table_del(key: i32);
}

// #[no_mangle]
// pub static mut SOURCE: [i8; 20] = [0; 20];
// #[no_mangle]
// pub static mut DESTINATION: [i8; 20] = [0; 20];
// #[no_mangle]
// pub static mut DNS_PACKET: [u8; 512] = [0; 512];

#[no_mangle]
extern "C" fn dns_query(source: u32, destination: u32, dns_packet: *const [u8]) {
    unsafe {
        let timestamp = clock_ns();
        // let source = CString::from_raw(SOURCE.as_mut_ptr());
        // let destination = CString::from_raw(DESTINATION.as_mut_ptr());

        match Packet::parse(&*dns_packet) {
            Ok(dns) => {
                let id = dns.header.id;

                let s = format!(
                    "wasm3: {}: dns_query {} -> source ip: {}, destination ip: {}",
                    timestamp,
                    id,
                    Ipv4Addr::from(source),
                    Ipv4Addr::from(destination),
                    // source.to_string_lossy(),
                    // destination.to_string_lossy(),
                );

                _debug(&s);
                _debug(&format!("wasm3: {:?}", dns));

                let turnaround = DnsTurnaround {
                    name: dns.questions[0].qname.to_string(),
                    records: Vec::new(),
                    latency_ns: timestamp,
                    client: Ipv4Addr::from(source).to_string(),
                    server: Ipv4Addr::from(destination).to_string(),
                    response_code: dns.header.response_code.into(),
                };
                add_packet(id as i32, turnaround);
                // DNS_PACKETS.lock().unwrap().insert(id, turnaround);
            }
            Err(e) => {
                _debug(&format!("wasm3: error: {:?}", e));
            }
        }
    }
}

#[no_mangle]
extern "C" fn dns_response(source: u32, destination: u32, dns_packet: *const [u8]) {
    unsafe {
        let timestamp = clock_ns();
        // let source = CString::from_raw(SOURCE.as_mut_ptr());
        // let destination = CString::from_raw(DESTINATION.as_mut_ptr());

        match Packet::parse(&*dns_packet) {
            Ok(dns) => {
                let id = dns.header.id;

                let s = format!(
                    "wasm3: {}, dns_response {} -> source ip: {}, destination ip: {}",
                    timestamp,
                    id,
                    Ipv4Addr::from(source),
                    Ipv4Addr::from(destination),
                    // source.to_string_lossy(),
                    // destination.to_string_lossy(),
                );

                _debug(&s);
                _debug(&format!("wasm3: {:?}", dns));

                // let mut packets = DNS_PACKETS.lock().unwrap();
                let packet = get_packet(id as i32);

                // match packets.get_mut(&id) {
                match packet {
                    Some(mut t) => {
                        t.records = dns
                            .answers
                            .into_iter()
                            .map(|a| format!("{:?}", a.data))
                            .collect();
                        t.latency_ns = timestamp - t.latency_ns;
                        t.response_code = dns.header.response_code.into();
                        let json = serde_json_wasm::to_string(&t).unwrap() + "\n";
                        submit_metric(&json);                
                        table_del(id as i32);
                    }
                    None => {
                        _debug("wasm3: can't find entry in hashmap");
                    }
                }
            }
            Err(e) => {
                _debug(&format!("wasm3: error: {:?}", e));
            }
        }

        
        let packet_keys = get_packet_keys();
        for i in packet_keys {
            let packet = get_packet(i);
            match packet {
                Some(mut v) => {
                    let is_timeouted = (timestamp - v.latency_ns) > 1000000000;
                    if is_timeouted {
                        v.response_code = 255;
                        let json = serde_json_wasm::to_string(&v).unwrap() + "\n";
                        submit_metric(&json);
                        table_del(i);
                    }
                }
                None => {
                    _debug(&format!("wasm3: cant find entry in hashmap for key: {:?}", i));
                }
            }
        }

        // for (_, v) in DNS_PACKETS.lock().unwrap().iter_mut().next() {
        //     let is_timeouted = (timestamp - v.latency_ns) > 1000000000;
        //     if is_timeouted {
        //         v.response_code = 255;
        //         let json = serde_json_wasm::to_string(&v).unwrap() + "\n";
        //         submit_metric(&json);
        //     }
        // }

        // _debug(&format!(
        //     "wasm3: dns packets in memory: {:?}",
        //     DNS_PACKETS.lock().unwrap().len()
        // ));

        // DNS_PACKETS
        //     .lock()
        //     .unwrap()
        //     .retain(|_, v: &mut DnsTurnaround| ((timestamp - v.latency_ns) < 1000000000));
    }
}

fn get_packet_keys() -> Vec<i32> {
    unsafe {
        // TODO remove this i64 based return type once the multi value RawFunction 
        // return type gets supported by wasm3 (baluchicken)
        let res = table_keys();
        
        let ptr: i32 = (res >> 32) as i32;
        let len: i32 = res as i32;
        
        let rawkeys = slice::from_raw_parts(ptr as *const i32, len as usize);
        
        return rawkeys.to_vec()
    }
}

fn get_packet(id: i32) -> Option<DnsTurnaround> {
    unsafe {
        // TODO remove this i64 based return type once the multi value RawFunction 
        // return type gets supported by wasm3 (baluchicken)
        let res = table_get(id);

        let ptr: i32 = (res >> 32) as i32; 
        let len: i32 = res as i32;

        let rawdata = slice::from_raw_parts(ptr as *const u8, len as usize);

        let data: Result<DnsTurnaround, _> = serde_json_wasm::from_str(str::from_utf8(rawdata).unwrap());
        data.ok()
    }
}

fn add_packet(id: i32, value: DnsTurnaround) {
    unsafe{
    let mut rawdata = serde_json_wasm::to_vec(&value).unwrap();
    let p = rawdata.as_mut_ptr();
    let lenght = rawdata.len();

    table_add(id,p as i32, lenght as i32)
    }
}

fn main() {
    // unsafe {
    //     _debug("wasm3: hello world");
    // }
}
