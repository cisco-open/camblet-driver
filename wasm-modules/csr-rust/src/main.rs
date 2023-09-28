/*
 * The MIT License (MIT)
 * Copyright (c) 2023 Cisco and/or its affiliates. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

use std::str::FromStr;
use std::str;

use x509_cert::builder::{RequestBuilder, Builder};
use x509_cert::der::EncodePem;
use x509_cert::der::asn1::Ia5String;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::name::GeneralName::{DnsName, UniformResourceIdentifier, Rfc822Name};
use x509_cert::name::Name;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, LineEnding};
use rsa::sha2::Sha256;
use rsa::RsaPrivateKey;

// import some WASM runtime functions from the module `env`
#[link(wasm_import_module = "env")]
extern "C" {
    fn _debug(s: &str) -> i32;
}

/// Allocate memory into the module's linear memory
/// and return the offset to the start of the block.
#[no_mangle]
pub fn csr_malloc(len: usize) -> *mut u8 {
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

/// Free memory from the module's linear memory
#[no_mangle]
pub unsafe fn csr_free(ptr: *mut u8, size: usize) {
    let data = Vec::from_raw_parts(ptr, size, size);

    std::mem::drop(data);
}

#[macro_export]
macro_rules! println {
    () => {
        _debug("\n")
    };
    ($($arg:tt)*) => {{
        let s = format!($($arg)*);
        _debug(&s);
    }};
}


//Using single return value since the multi return value is still buggy. See https://github.com/rust-lang/rust/issues/73755
#[no_mangle]
pub unsafe extern "C" fn csr_gen(priv_key: &[u8], subject: &[u8], dns: &[u8], uri: &[u8], email: &[u8], ip: &[u8]) -> i64 {

    let private_key = match RsaPrivateKey::from_pkcs8_der(priv_key) {
        Ok(key) => key,
        Err(err) => { println!("error parsing private key: {}", err); return 0 },
    };
    let signing_key = SigningKey::<Sha256>::new(private_key);

    // Parse cert related parameters
    let raw_subject = match str::from_utf8(&subject) {
        Ok(s) => s,
        Err(err) => { println!("error parsing subject: {}", err); return 0},
    };
    let subject = match Name::from_str(raw_subject.trim_end_matches(char::from(0))) {
        Ok(name) => name,
        Err(err) => { println!("error processing subject: {}", err); return 0 },
    };
    use std::net::IpAddr;

    let raw_ip = match str::from_utf8(&ip) {
        Ok(ip) => ip,
        Err(err) => { println!("error parsing ip: {}", err); return 0},
    };
    let parsed_ip: IpAddr = match raw_ip.trim_end_matches(char::from(0)).parse() {
        Ok(pip) => pip,
        Err(err) => { println!("error processing ip: {}", err); return 0},
    };

    let raw_dns = match Ia5String::new(&dns) {
        Ok(dns) => dns,
        Err(err) => { println!("error parsing dns name: {}", err); return 0},
    };

    let raw_uri = match Ia5String::new(&uri) {
        Ok(uri) => uri,
        Err(err) => { println!("error parsing uri name: {}", err); return 0},
    };

    let raw_email = match Ia5String::new(&email) {
        Ok(email) => email,
        Err(err) => {println!("error parsing email: {}", err); return 0},
    };
    
    let mut builder = match RequestBuilder::new(subject, &signing_key) {
        Ok(builder) => builder,
        Err(err) => { println!("error creating builder: {}", err); return 0 },
    };

    let _ = match builder.add_extension(&SubjectAltName(vec![
        DnsName(raw_dns), 
        UniformResourceIdentifier(raw_uri),
        GeneralName::from(parsed_ip),
        Rfc822Name(raw_email),
        ])) {
            Ok(()) => (),
            Err(err) => { println!("error adding extension Subject Alt Name to cert req builder: {}", err); return 0},
    };

    let cert_req = match builder.build() {
        Ok(cert_req) => cert_req,
        Err(err) => { println!("error building cert request: {}", err); return 0 },
    };
    let encoded_csr = match cert_req.to_pem(LineEnding::LF) {
        Ok(encoded_csr) => encoded_csr,
        Err(err) => { println!("error encoding cert request: {}", err); return 0 },
    };

    let encoded_csr_ptr = encoded_csr.as_ptr();
    let encoded_csr_len = encoded_csr.len();

    // We must tell the rust compiler to abandon the buffer otherwise it will be freed before we can use it at the host side.
    std::mem::forget(encoded_csr);

    ((encoded_csr_ptr as i64) << 32) | (encoded_csr_len as i64)
}

fn main() {}