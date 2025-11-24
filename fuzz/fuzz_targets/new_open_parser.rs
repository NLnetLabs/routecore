#![no_main]

use libfuzzer_sys::fuzz_target;
use routecore::bgp::message_ng::{common::{Header, MessageType}, Open};
use zerocopy::TryFromBytes;

fuzz_target!(|data: &[u8]| {
    match Open::try_from_full_pdu(&data) {
        Ok(open) => {
            let (h,_) = Header::try_ref_from_prefix(&data).unwrap();
            assert_eq!(h.msg_type, MessageType::OPEN);
            assert_eq!(usize::from(h.length), data.len());

            for cap in open.capabilities() {
                match cap {
                    Ok(_cap) => { /* TODO */ } 
                    Err(_e) => { }
                }
            }

        }
        Err(_) => { }
    }
});
