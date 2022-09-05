use dns_parser::Packet as DnsPacket;
use etherparse::*;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::slice;
use std::str;
use serde_json as serde_json;

#[derive(Debug, Default, Serialize, Deserialize)]
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

#[macro_export]
macro_rules! println {
    () => {
        _debug("\n")
    };
    ($($arg:tt)*) => {{
        _debug(&format!($($arg)*));
    }};
}

#[no_mangle]
extern "C" fn packet_out(packet: &[u8]) {
    unsafe {
        let mut query = DnsTurnaround::default();
        query.latency_ns = clock_ns();

        match PacketHeaders::from_ip_slice(packet) {
            Err(err) => {
                println!("wasm3: ip packet parser error: {:?}", err);
                return;
            }
            Ok(value) => {
                match value.ip {
                    Some(IpHeader::Version4(hdr, _ext)) => {
                        query.client = Ipv4Addr::from(hdr.source).to_string();
                        query.server = Ipv4Addr::from(hdr.destination).to_string();
                    }
                    Some(IpHeader::Version6(hdr, _ext)) => {
                        query.client = Ipv6Addr::from(hdr.source).to_string();
                        query.server = Ipv6Addr::from(hdr.destination).to_string();
                    }
                    None => return,
                };

                match value.transport {
                    Some(TransportHeader::Udp(hdr)) => {
                        if hdr.destination_port != 53 {
                            println!(
                                "wasm3: UDP packet to {} -> {}",
                                hdr.source_port, hdr.destination_port
                            );
                            return;
                        }

                        // println!("dns ip: {:?}", value.ip);
                        // println!("dns transport: {:?}", value.transport);

                        match DnsPacket::parse(value.payload) {
                            Ok(dns) => {
                                let id = dns.header.id;

                                println!(
                                    "wasm3: {}: dns_query {} -> source ip: {}, destination ip: {}",
                                    query.latency_ns, id, query.client, query.server,
                                );
                                println!("wasm3: {:?}", dns);

                                query.name = dns.questions[0].qname.to_string();
                                query.records = Vec::new();
                                query.response_code = dns.header.response_code.into();

                                add_packet(id as i32, query);
                            }
                            Err(e) => {
                                println!("wasm3: dns packet parser error: {:?}", e);
                                return;
                            }
                        }
                    }
                    None => return,
                    _ => {}
                };
            }
        };
    }
}

#[no_mangle]
extern "C" fn packet_in(packet: &[u8]) {
    unsafe {
        let timestamp = clock_ns();
        let mut query = DnsTurnaround::default();
        query.latency_ns = timestamp;

        match PacketHeaders::from_ip_slice(packet) {
            Err(err) => {
                println!("wasm3: ip packet parser error: {:?}", err);
                return;
            }
            Ok(value) => {
                match value.ip {
                    Some(IpHeader::Version4(hdr, _ext)) => {
                        query.client = Ipv4Addr::from(hdr.source).to_string();
                        query.server = Ipv4Addr::from(hdr.destination).to_string();
                    }
                    Some(IpHeader::Version6(hdr, _ext)) => {
                        query.client = Ipv6Addr::from(hdr.source).to_string();
                        query.server = Ipv6Addr::from(hdr.destination).to_string();
                    }
                    None => return,
                };

                match value.transport {
                    Some(TransportHeader::Udp(hdr)) => {
                        if hdr.source_port != 53 {
                            println!(
                                "wasm3: UDP packet to {} -> {}",
                                hdr.source_port, hdr.destination_port
                            );
                            return;
                        }

                        // println!("dns ip: {:?}", value.ip);
                        // println!("dns transport: {:?}", value.transport);

                        match DnsPacket::parse(value.payload) {
                            Ok(dns) => {
                                let id = dns.header.id;

                                println!(
                                    "wasm3: {}: dns_answer {} -> source ip: {}, destination ip: {}",
                                    query.latency_ns, id, query.client, query.server,
                                );

                                println!("wasm3: {:?}", dns);

                                match get_packet(id as i32) {
                                    Some(mut t) => {
                                        t.records = dns
                                            .answers
                                            .into_iter()
                                            .map(|a| format!("{:?}", a.data))
                                            .collect();
                                        t.latency_ns = query.latency_ns - t.latency_ns;
                                        t.response_code = dns.header.response_code.into();
                                        let json = serde_json::to_string(&t).unwrap() + "\n";
                                        submit_metric(&json);
                                        table_del(id as i32);
                                    }
                                    None => {
                                        println!("wasm3: can't find entry in hashmap");
                                    }
                                }

                                let packet_keys = get_packet_keys();
                                for i in packet_keys {
                                    let packet = get_packet(i);
                                    match packet {
                                        Some(mut v) => {
                                            let is_timeouted =
                                                (timestamp - v.latency_ns) > 1000000000;
                                            if is_timeouted {
                                                v.response_code = 255;
                                                let json =
                                                    serde_json::to_string(&v).unwrap() + "\n";
                                                submit_metric(&json);
                                                table_del(i);
                                            }
                                        }
                                        None => {
                                            println!(
                                                "wasm3: cant find entry in hashmap for key: {:?}",
                                                i
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                println!("wasm3: dns packet parser error: {:?}", e);
                                return;
                            }
                        }
                    }
                    None => return,
                    _ => {}
                };
            }
        };
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

        return rawkeys.to_vec();
    }
}

fn get_packet(id: i32) -> Option<DnsTurnaround> {
    unsafe {
        // TODO remove this i64 based return type once the multi value RawFunction
        // return type gets supported by wasm3 (baluchicken)
        let res = table_get(id);
        if res == 0 {
            return None;
        }

        let ptr: i32 = (res >> 32) as i32;
        let len: i32 = res as i32;

        let rawdata = slice::from_raw_parts(ptr as *const u8, len as usize);

        let data: Result<DnsTurnaround, _> = serde_json::from_slice(rawdata);
        data.ok()
    }
}

fn add_packet(id: i32, value: DnsTurnaround) {
    unsafe {
        let mut rawdata = serde_json::to_vec(&value).unwrap();
        let p = rawdata.as_mut_ptr();
        let lenght = rawdata.len();

        table_add(id, p as i32, lenght as i32);
    }
}

fn main() {}
