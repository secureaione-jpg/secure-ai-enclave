//! Ask the Nitro Security Module for an attestation document.
//!
//! The one job src/attest.ts cannot do from Node: talking to /dev/nsm needs the
//! NSM ioctl protocol, and the alternative to this binary is a native addon
//! inside the service itself. A separate process keeps the trusted computing
//! base easier to read — the service spawns it, gets base64 on stdout, and has
//! no compiled dependency of its own.
//!
//! Contract, matched exactly in enclave/src/attest.ts:
//!
//!   nsm-cli attest --nonce <base64> --public-key <base64>
//!
//! Prints the COSE_Sign1 attestation document as base64 on stdout. Anything
//! else is a failure and goes to stderr with a non-zero exit, because a caller
//! that cannot tell "here is a document" from "I could not get one" would
//! report an unattested enclave as attested.
//!
//! `public_key` is the field that matters. Binding this boot's public key into
//! the signed document is what lets a client encrypt to an enclave it has
//! verified, rather than merely learning that some enclave exists.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_bytes::ByteBuf;

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

/// Reads `--name value` out of the argument list. Absent is not an error here:
/// the NSM accepts a document with any of the three optional fields missing,
/// and refusing one would make this stricter than the thing it wraps.
fn flag(args: &[String], name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1).cloned()
}

fn decode(label: &str, value: Option<String>) -> Option<ByteBuf> {
    let raw = value?;
    match B64.decode(raw.as_bytes()) {
        Ok(bytes) => Some(ByteBuf::from(bytes)),
        // Bad base64 is a caller bug, and silently treating it as absent would
        // produce a document that verifies and proves the wrong thing.
        Err(err) => fail(&format!("{label} is not valid base64: {err}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("attest") {
        fail("usage: nsm-cli attest --nonce <base64> --public-key <base64>");
    }

    let nonce = decode("--nonce", flag(&args, "--nonce"));
    let public_key = decode("--public-key", flag(&args, "--public-key"));
    let user_data = decode("--user-data", flag(&args, "--user-data"));

    let fd = nsm_init();
    if fd < 0 {
        fail("could not open /dev/nsm — this is not running inside an enclave");
    }

    let response = nsm_process_request(
        fd,
        Request::Attestation {
            user_data,
            nonce,
            public_key,
        },
    );
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => {
            println!("{}", B64.encode(document));
        }
        Response::Error(err) => fail(&format!("NSM refused the request: {err:?}")),
        other => fail(&format!("NSM returned an unexpected response: {other:?}")),
    }
}
