#![no_main]

use libfuzzer_sys::fuzz_target;
use routecore::bgp::message::OpenMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(open) =  OpenMessage::from_octets(data) {
        open.capabilities().count();
    }
});



