use domain::base::Message;
use pdu::{Ip, Ipv4, Udp};
use postcard;
use serde::{Deserialize, Serialize};
use serde_json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice;
use std::str;

#[derive(Debug, Serialize, Deserialize)]
struct DnsTurnaround {
    // name: String,
    questions: u16,
    answers: u16,
    latency_ns: i64,
    client: IpAddr,
    server: IpAddr,
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
    fn table_get(id: i32) -> (i32, i32);
    fn table_keys() -> (i32, i32);
    fn table_add(key: i32, value_ptr: i32, value_length: i32);
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
unsafe extern "C" fn packet_out(packet: &[u8]) {
    let now = clock_ns();
    match Ip::new(&packet) {
        Ok(Ip::Ipv4(ipv4_pdu)) => {
            match ipv4_pdu.inner() {
                Ok(Ipv4::Udp(udp_pdu)) => {
                    if udp_pdu.destination_port() == 53 {
                        println!("[ipv4] possible DNS question");
                        match udp_pdu.into_inner() {
                            Ok(Udp::Raw(data)) => {
                                println!("[ipv4] parsing DNS question: {:?}", data);
                                match Message::from_octets(data) {
                                    Ok(dns) => {
                                        println!(
                                            "[ipv4] parsed DNS header: {:?}",
                                            dns.header_section()
                                        );
                                        println!(
                                            "[ipv4] parsed DNS opcode: {:?}",
                                            dns.header().opcode()
                                        );
                                        println!(
                                            "[ipv4] parsed DNS rcode: {:?}",
                                            dns.header().rcode()
                                        );
                                        println!("[ipv4] parsed DNS id: {:?}", dns.header().id());
                                        println!(
                                            "[ipv4] parsed DNS questions: {:?}",
                                            dns.header_counts().qdcount()
                                        );

                                        let turnaround = DnsTurnaround {
                                            latency_ns: now,
                                            questions: dns.header_counts().qdcount(),
                                            answers: 0,
                                            client: IpAddr::V4(Ipv4Addr::from(
                                                ipv4_pdu.source_address(),
                                            )),
                                            server: IpAddr::V4(Ipv4Addr::from(
                                                ipv4_pdu.destination_address(),
                                            )),
                                            response_code: 0,
                                        };

                                        // match dns.sole_question() {
                                        //     Ok(question) => {
                                        //         match question.qname().to_dname::<heapless::Vec<u8, 256>>() {
                                        //             Ok(dname) => println!("dname: {}", dname),
                                        //             Err(e) => println!("error: {}", e)
                                        //         }
                                        //     }
                                        //     Err(e) => panic!("fatal error {}", e),
                                        // }

                                        add_packet(dns.header().id(), &turnaround);
                                    }
                                    Err(e) => {
                                        panic!("Ipv4Pdu::inner() DNS parser failure: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                panic!("UdpPdu::inner() DNS parser failure: {:?}", e);
                            }
                        }
                    }
                }
                Ok(_) => {
                    // println!(
                    //     "[ipv4] protocol: 0x{:02x} not supported",
                    //     ipv4_pdu.protocol()
                    // );
                    return;
                }
                Err(e) => {
                    panic!("Ipv4Pdu::inner() parser failure: {:?}", e);
                }
            }
            println!(
                "[ipv4] source_address: {:?}",
                Ipv4Addr::from(ipv4_pdu.source_address())
            );
            println!(
                "[ipv4] destination_address: {:?}",
                Ipv4Addr::from(ipv4_pdu.destination_address())
            );
            println!("[ipv4] protocol: 0x{:02x}", ipv4_pdu.protocol());
            // upper-layer protocols can be accessed via the inner() method (not shown)
        }
        Ok(Ip::Ipv6(ipv6_pdu)) => {
            println!(
                "[ipv6] source_address: {:?}",
                Ipv6Addr::from(ipv6_pdu.source_address())
            );
            println!(
                "[ipv6] destination_address: {:?}",
                Ipv6Addr::from(ipv6_pdu.destination_address())
            );
            println!("[ipv6] protocol: 0x{:02x}", ipv6_pdu.computed_protocol());
            // upper-layer protocols can be accessed via the inner() method (not shown)
        }
        Err(e) => {
            panic!("EthernetPdu::inner() parser failure: {:?}", e);
        }
    }
}

#[no_mangle]
unsafe extern "C" fn packet_in(packet: &[u8]) {
    let now = clock_ns();
    match Ip::new(&packet) {
        Ok(Ip::Ipv4(ipv4_pdu)) => {
            match ipv4_pdu.inner() {
                Ok(Ipv4::Udp(udp_pdu)) => {
                    if udp_pdu.source_port() == 53 {
                        println!("[ipv4] possible DNS answer");
                        match udp_pdu.into_inner() {
                            Ok(Udp::Raw(data)) => {
                                println!("[ipv4] parsing DNS answer: {:?}", data);
                                match Message::from_octets(data) {
                                    Ok(dns) => {
                                        println!(
                                            "[ipv4] parsed DNS header: {:?}",
                                            dns.header_section()
                                        );
                                        println!(
                                            "[ipv4] parsed DNS opcode: {:?}",
                                            dns.header().opcode()
                                        );
                                        println!(
                                            "[ipv4] parsed DNS rcode: {:?}",
                                            dns.header().rcode()
                                        );
                                        println!("[ipv4] parsed DNS id: {:?}", dns.header().id());
                                        println!(
                                            "[ipv4] parsed DNS answers: {:?}",
                                            dns.header_counts().ancount()
                                        );

                                        match get_packet(dns.header().id() as i32) {
                                            Some(mut t) => {
                                                t.latency_ns = now - t.latency_ns;
                                                t.response_code = dns.header().rcode().to_int();
                                                let json =
                                                    serde_json::to_string(&t).unwrap() + "\n";
                                                submit_metric(&json);
                                                table_del(dns.header().id() as i32);
                                            }
                                            None => {
                                                println!("wasm dns: can't find entry in hashmap");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        panic!("Ipv4Pdu::inner() DNS parser failure: {:?}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                panic!("UdpPdu::inner() DNS parser failure: {:?}", e);
                            }
                        }
                    }
                }
                Ok(_) => {
                    // println!(
                    //     "[ipv4] protocol: 0x{:02x} not supported",
                    //     ipv4_pdu.protocol()
                    // );
                    return;
                }
                Err(e) => {
                    panic!("Ipv4Pdu::inner() parser failure: {:?}", e);
                }
            }
            println!(
                "[ipv4] source_address: {:?}",
                Ipv4Addr::from(ipv4_pdu.source_address())
            );
            println!(
                "[ipv4] destination_address: {:?}",
                Ipv4Addr::from(ipv4_pdu.destination_address())
            );
            println!("[ipv4] protocol: 0x{:02x}", ipv4_pdu.protocol());
            // upper-layer protocols can be accessed via the inner() method (not shown)
        }
        Ok(Ip::Ipv6(ipv6_pdu)) => {
            println!(
                "[ipv6] source_address: {:?}",
                Ipv6Addr::from(ipv6_pdu.source_address())
            );
            println!(
                "[ipv6] destination_address: {:?}",
                Ipv6Addr::from(ipv6_pdu.destination_address())
            );
            println!("[ipv6] protocol: 0x{:02x}", ipv6_pdu.computed_protocol());
            // upper-layer protocols can be accessed via the inner() method (not shown)
        }
        Err(e) => {
            panic!("EthernetPdu::inner() parser failure: {:?}", e);
        }
    }

    gc_timeouted_packets(now);
}

fn gc_timeouted_packets(now: i64) {
    let packet_keys = get_packet_keys();
    for id in packet_keys {
        let packet = get_packet(id);
        match packet {
            Some(mut v) => {
                let is_timeouted = (now - v.latency_ns) > 1000000000;
                if is_timeouted {
                    v.response_code = 255;
                    let json = serde_json::to_string(&v).unwrap() + "\n";
                    unsafe {
                        println!("dns: deleting timeouted question for request id: {}", id);
                        table_del(id);
                        submit_metric(&json);
                    }
                }
            }
            _ => {}
        }
    }
}

fn get_packet_keys() -> Vec<i32> {
    unsafe {
        let (ptr, len) = table_keys();
        let rawkeys = slice::from_raw_parts(ptr as *const i32, len as usize);

        return rawkeys.to_vec();
    }
}

#[no_mangle]
fn get_packet(id: i32) -> Option<DnsTurnaround> {
    let rawdata: &[u8];

    unsafe {
        let (ptr, len) = table_get(id);
        if ptr == 0 {
            return None;
        }

        rawdata = slice::from_raw_parts(ptr as *const u8, len as usize);
    }

    // let data: Result<DnsTurnaround, _> = serde_json::from_slice(rawdata);
    let data = postcard::from_bytes(rawdata);
    match data {
        Ok(dns) => Some(dns),
        Err(e) => {
            panic!("there was an error parsing a value from the table: {}", e);
        }
    }
}

fn add_packet(id: u16, value: &DnsTurnaround) {
    // let rawdata = serde_json::to_vec(value).unwrap();
    let rawdata = postcard::to_vec::<DnsTurnaround, 128>(value).unwrap();

    unsafe {
        table_add(id as i32, rawdata.as_ptr() as i32, rawdata.len() as i32);
    }
}

fn main() {}
