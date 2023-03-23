#[link(wasm_import_module = "env")]
extern "C" {
    fn _debug(s: &str) -> i32;
}

fn main() {
    unsafe {
        _debug("Hello, world!");
    }
}
