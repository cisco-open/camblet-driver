use bytes::Bytes;
use std::ffi::CString;
use dns_message_parser::Dns;

// import a WASM runtime function called `_debug` from the module `env`
#[link(wasm_import_module = "env")]
extern "C" {
    fn _debug(s: &str) -> i32;
}

#[no_mangle]
pub static mut SOURCE: [i8; 20] = [0; 20];
#[no_mangle]
pub static mut DESTINATION: [i8; 20] = [0; 20];
#[no_mangle]
pub static mut DNS_NAME: [i8; 256] = [0; 256];


// source: &str, destination: &str
#[no_mangle]
extern "C" fn dns_query(id: i32) -> bool {
    unsafe {
        let source = CString::from_raw(SOURCE.as_mut_ptr());
        let destination = CString::from_raw(DESTINATION.as_mut_ptr());
        let dns_name = CString::from_raw(DNS_NAME.as_mut_ptr());

        let mut s = format!(
            "wasm3: dns_query {} -> source ip: {}, destination ip: {}, dns name: {}",
            id,
            source.to_string_lossy(),
            destination.to_string_lossy(),
            dns_name.to_string_lossy(),
        );

        _debug(&s);

        // let msg = b"\xdb\x1c\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\
        // \x03\x6f\x72\x67\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x0a\x00\
        // \x00\x0a";
    
        // let bytes = Bytes::copy_from_slice(&msg[..]);

        // match Dns::decode(bytes) {
        //     Ok(dns) => {
        //         s = format!("{:?}", dns);
        //         _debug(&s);
        //     }
        //     Err(e) => {
        //         s = format!("{:?}", e);
        //         _debug(&s);
        //     }
        // }
    }
    
    return true
}

#[no_mangle]
// source: &str, destination: &str
extern "C" fn dns_response(id: i32, answers: i32, ttl: i32) -> bool {
    unsafe {
        let source = CString::from_raw(SOURCE.as_mut_ptr());
        let destination = CString::from_raw(DESTINATION.as_mut_ptr());
        let dns_name = CString::from_raw(DNS_NAME.as_mut_ptr());

        let s = format!(
            "wasm3: dns_response {} -> source ip: {}, destination ip: {}, dns name: {}, answers: {}, ttl: {}",
            id,
            source.to_string_lossy(),
            destination.to_string_lossy(),
            dns_name.to_string_lossy(),
            answers,
            ttl,
        );

        _debug(&s);
    }
    
    return true
}

fn main() {
    unsafe {
        _debug("hello world");
    }
}
