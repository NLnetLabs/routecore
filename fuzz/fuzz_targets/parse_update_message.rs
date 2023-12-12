#![no_main]

use libfuzzer_sys::fuzz_target;
use routecore::bgp::message::{UpdateMessage, SessionConfig};
use routecore::bgp::message::update_builder::UpdateBuilder;

fuzz_target!(|data: (&[u8], SessionConfig)| {
    if let Ok(upd) =  UpdateMessage::from_octets(data.0, data.1) {
        if let Ok(pas) = upd.path_attributes() {
            for pa in pas.into_iter() {
                if let Ok(pa) = pa {
                    let _ = pa.to_owned();
                }
            }
        }
        /*
        if let Ok(builder) = UpdateBuilder::from_update_message(
            &upd,
            data.1,
            target,
        ) {
            let _ = builder.into_message(); //.unwrap();
        }
        */
    }
});



