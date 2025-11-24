#![no_main]

use libfuzzer_sys::fuzz_target;
use routecore::bgp::message_ng::{common::{Header, MessageType, SessionConfig}, update::CheckedParts, Update};
use zerocopy::TryFromBytes;

fuzz_target!(|data: &[u8]| {
    
    match Update::try_from_full_pdu(&data) {
        Ok(update) => {
            let (h,_) = Header::try_ref_from_prefix(&data).unwrap();
            assert_eq!(h.msg_type, MessageType::UPDATE);
            assert_eq!(usize::from(h.length), data.len());

            let sc = SessionConfig::default();
            let CheckedParts {
                checked_mp_attributes,
                checked_conv_attributes,
                mp_reach,
                mp_unreach
            } = update.into_checked_parts(&sc);

            if let Some(pab) = checked_mp_attributes {
                for pa in pab.as_ref().iter() {
                    match pa {
                        Ok(_rpa) => { /* TODO */ } 
                        Err(_e) => { }
                    }
                }
            }
            if let Some(pab) = checked_conv_attributes {
                for pa in pab.as_ref().iter() {
                    match pa {
                        Ok(_rpa) => { /* TODO */ } 
                        Err(_e) => { }
                    }
                }
            }

            // TODO iterate mp_reach

            // TODO iterate mp_unreach

        }
        Err(_) => { }
    }
});
