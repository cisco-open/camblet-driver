use std::ffi::CString;

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
// source: &str, destination: &str
extern "C" fn ip_debugger() -> bool {
    unsafe {
        let source = CString::from_raw(SOURCE.as_mut_ptr());
        let destination = CString::from_raw(DESTINATION.as_mut_ptr());

        let s = format!(
            "source ip: {}, destination ip: {}",
            source.to_string_lossy(),
            destination.to_string_lossy()
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
