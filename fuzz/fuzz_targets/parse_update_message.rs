#![no_main]

use libfuzzer_sys::fuzz_target;
use routecore::bgp::message::{UpdateMessage, SessionConfig};
use routecore::bgp::message::update_builder::UpdateBuilder;

fuzz_target!(|data: (&[u8], SessionConfig)| {
    if let Ok(upd) =  UpdateMessage::from_octets(data.0, &data.1) {
        if let Ok(pas) = upd.path_attributes() {
            for pa in pas.into_iter() {
                let _ = pa.unwrap().to_owned();
            }
        }
        if let Ok(iter) =  upd.announcements() {
            iter.count();
        }
        if let Ok(iter) =  upd.withdrawals() {
            iter.count();
        }
    }
});



