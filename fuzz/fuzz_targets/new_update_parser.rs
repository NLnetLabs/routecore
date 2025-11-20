#![no_main]

use libfuzzer_sys::fuzz_target;
use routecore::bgp::message_ng::{common::{Header, MessageType}, Update};
use zerocopy::TryFromBytes;

fuzz_target!(|data: &[u8]| {
    
    match Update::try_from_full_pdu(&data) {
        Ok(update) => {
            let (h,_) = Header::try_ref_from_prefix(&data).unwrap();
            assert_eq!(h.msg_type, MessageType::UPDATE);
            assert_eq!(usize::from(h.length), data.len());
        }
        Err(_) => { }
    }
});
