#![no_main]

use libfuzzer_sys::fuzz_target;
use routecore::bgp::message::{Message, SessionConfig};

fuzz_target!(|data: (&[u8], Option<SessionConfig>)| {
    let _ =  Message::from_octets(data.0, data.1);
});



