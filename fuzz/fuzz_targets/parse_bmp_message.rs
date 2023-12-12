#![no_main]

use libfuzzer_sys::fuzz_target;
use routecore::bmp::message::Message;


fuzz_target!(|data: &[u8]| {
    let _ =  Message::from_octets(data);
});

